//go:build linux || (darwin && cgo)

// Package tray adapts the menu and animation models to a native system tray.
package tray

import (
	"context"
	"runtime"
	"strings"
	"sync"

	"fyne.io/systray"

	"github.com/avhn/fortix/internal/tray/animate"
	"github.com/avhn/fortix/internal/tray/model"
)

// desktop owns menu items and click forwarding until the controller terminates.
// Rendering is serialized by the controller; icon updates use the native adapter.
type desktop struct {
	ctx      context.Context
	actions  chan string
	updates  chan animate.Update
	items    map[string]*systray.MenuItem
	removed  map[string]chan struct{}
	profiles *systray.MenuItem
	clicks   sync.WaitGroup
}

// Actions exposes typed action identifiers without exposing toolkit objects.
func (d *desktop) Actions() <-chan string { return d.actions }

// SetIcon installs template icons on macOS and colored PNGs on Linux. The native
// API has no error result; input validity is enforced by the icon cache upstream.
func (*desktop) SetIcon(data []byte) error {
	if runtime.GOOS == "darwin" {
		systray.SetTemplateIcon(data, data)
	} else {
		systray.SetIcon(data)
	}
	return nil
}

// item creates a native item and one cancellable click-forwarding worker.
// Removing an obsolete item cancels its worker independently of toolkit channels.
func (d *desktop) item(id, title string, parent *systray.MenuItem) *systray.MenuItem {
	if item := d.items[id]; item != nil {
		return item
	}
	var item *systray.MenuItem
	switch {
	case parent != nil:
		item = parent.AddSubMenuItemCheckbox(title, title, false)
	case id == "animate_icon":
		item = systray.AddMenuItemCheckbox(title, title, false)
	default:
		item = systray.AddMenuItem(title, title)
	}
	d.items[id] = item
	removed := make(chan struct{})
	d.removed[id] = removed
	d.clicks.Add(1)
	go func() {
		defer d.clicks.Done()
		forwardClicks(d.ctx, removed, item.ClickedCh, d.actions, id)
	}()
	return item
}

// Render updates menu titles, availability and checks, and coalesces icon snapshots.
// Open logs is a submenu with one literal profile ID action per current profile.
func (d *desktop) Render(menu model.Menu) {
	wanted := make(map[string]bool, len(menu.Items)*2)
	count := 0
	for _, m := range menu.Items {
		wanted[m.ID] = true
		if strings.HasPrefix(m.ID, "profile:") {
			wanted["logs:"+strings.TrimPrefix(m.ID, "profile:")] = true
			count++
		}
	}
	for id, item := range d.items {
		if !wanted[id] {
			close(d.removed[id])
			delete(d.removed, id)
			item.Remove()
			delete(d.items, id)
		}
	}
	if count == 0 {
		d.profiles.Disable()
	} else {
		d.profiles.Enable()
	}
	for _, m := range menu.Items {
		var parent *systray.MenuItem
		if strings.HasPrefix(m.ID, "profile:") {
			parent = d.profiles
		}
		item := d.item(m.ID, m.Title, parent)
		item.SetTitle(m.Title)
		item.Show()
		if m.Enabled {
			item.Enable()
		} else {
			item.Disable()
		}
		if m.Checked {
			item.Check()
		} else {
			item.Uncheck()
		}
	}
	logs := d.items["open_logs"]
	for _, m := range menu.Items {
		if !strings.HasPrefix(m.ID, "profile:") {
			continue
		}
		id := strings.TrimPrefix(m.ID, "profile:")
		item := d.item("logs:"+id, id, logs)
		item.Show()
	}
	systray.SetTooltip(menu.Tooltip)
	update := animate.Update{Status: menu.Status, AnimateIcon: d.preference(menu)}
	select {
	case d.updates <- update:
	default:
		select {
		case <-d.updates:
		default:
		}
		d.updates <- update
	}
}

// preference reads the live animation checkbox from an immutable menu snapshot.
func (*desktop) preference(menu model.Menu) bool {
	for _, item := range menu.Items {
		if item.ID == "animate_icon" {
			return item.Checked
		}
	}
	return false
}

// runDesktop starts the toolkit on its required thread, then joins controller,
// animation and menu workers before returning. It never starts a privileged child.
func runDesktop(ctx context.Context, options Options) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	var result error
	systray.Run(func() {
		d := &desktop{ctx: ctx, actions: make(chan string, 32), updates: make(chan animate.Update, 1), items: make(map[string]*systray.MenuItem), removed: make(map[string]chan struct{}), profiles: systray.AddMenuItem("Profiles", "Toggle a VPN profile")}
		options.View = d
		animationDone := make(chan struct{})
		go func() {
			defer close(animationDone)
			a := animate.Animator{Platform: runtime.GOOS, Size: 22, Setter: d, Source: animate.SystemMotion{Platform: runtime.GOOS}}
			if a.Run(ctx, d.updates, animate.Update{Status: model.NotConnected, AnimateIcon: options.Preferences.AnimateIcon}) != nil {
				options.Report("Tray icon unavailable")
				cancel()
			}
		}()
		result = Run(ctx, options)
		cancel()
		<-animationDone
		d.clicks.Wait()
		close(done)
		systray.Quit()
	}, cancel)
	<-done
	return result
}
