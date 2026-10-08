package helper

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/avhn/fortix/internal/buildinfo"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/session"
)

// Status is a non-secret snapshot for one stored profile, including idle profiles.
// Since is the UTC time of the most recent state transition, or zero before startup.
type Status struct {
	Profile   string        `json:"profile"`
	State     session.Phase `json:"state"`
	Detail    string        `json:"detail"`
	Attempt   uint64        `json:"attempt"`
	Interface string        `json:"interface"`
	LocalIP   string        `json:"local_ip"`
	Since     time.Time     `json:"since"`
}

// profileState pairs a profile identifier with its current public phase.
type profileState struct {
	Profile string        `json:"profile"`
	State   session.Phase `json:"state"`
}

// dispatch executes one authorized, validated operation. opMu serializes mutations
// across clients, while each supervisor serializes process events and live replies.
// Result messages never contain raw storage or subprocess error text.
func (s *Server) dispatch(c *connection, r protocol.Request) protocol.Result {
	result := protocol.Result{Type: "result", ID: r.ID, OK: true}
	if r.Profile != "" && !ValidID(r.Profile) {
		return failure(r.ID, protocol.Invalid, "invalid profile id")
	}
	switch r.Op {
	case "hello":
		result.Data = struct {
			HelperVersion string `json:"helper_version"`
			Protocol      int    `json:"protocol"`
		}{buildinfo.Version, protocol.Version}
	case "subscribe":
		s.mu.Lock()
		c.subscribed = true
		s.mu.Unlock()
	case "profile.list", "status":
		ids, err := s.profileIDs()
		if err != nil {
			return storedFailure(r.ID, err)
		}
		statuses := make([]Status, 0, len(ids))
		profiles := make([]profileState, 0, len(ids))
		for _, id := range ids {
			p, err := s.store.Get(id)
			if err != nil {
				s.opts.Logger.Warn("skipping unreadable profile", "profile", id, "error", err)
				if a := s.actor(id); a != nil {
					statuses = append(statuses, a.snapshot())
					profiles = append(profiles, profileState{id, a.snapshot().State})
				}
				continue
			}
			status := Status{Profile: id, State: session.Disconnected}
			if a := s.actor(id); a != nil {
				status = a.snapshot()
			}
			statuses = append(statuses, status)
			profiles = append(profiles, profileState{p.ID, status.State})
		}
		if r.Op == "status" {
			result.Data = statuses
		} else {
			result.Data = profiles
		}
	case "profile.get":
		p, err := s.store.Get(r.Profile)
		if err != nil {
			return storedFailure(r.ID, err)
		}
		result.Data = p
	case "profile.put":
		p, err := profile.Decode(bytes.NewReader(r.ProfileJSON))
		if err != nil {
			return failure(r.ID, protocol.Invalid, "invalid profile")
		}
		if a := s.actor(p.ID); a != nil && !a.idle() {
			return failure(r.ID, protocol.Conflict, "profile is active")
		}
		// Certificate pins are helper-owned: imports cannot install or remove trust.
		stored, err := s.store.Get(p.ID)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return storedFailure(r.ID, err)
		}
		p.TrustedCert = ""
		if stored != nil {
			p.TrustedCert = stored.TrustedCert
		}
		data, err := json.Marshal(p)
		if err != nil {
			return storedFailure(r.ID, err)
		}
		p, err = s.store.Put(data)
		if err != nil {
			return storedFailure(r.ID, err)
		}
		if a := s.actor(p.ID); a != nil {
			a.call(controlInput{op: "replace", profile: p})
		}
	case "profile.delete":
		if a := s.actor(r.Profile); a != nil && !a.idle() {
			return failure(r.ID, protocol.Conflict, "profile is active")
		}
		if err := s.store.Delete(r.Profile); err != nil {
			return storedFailure(r.ID, err)
		}
		if a := s.actor(r.Profile); a != nil {
			a.call(controlInput{op: "retire"})
			<-a.done
			s.mu.Lock()
			delete(s.actors, r.Profile)
			s.mu.Unlock()
		}
	case "up":
		p, err := s.store.Get(r.Profile)
		if err != nil {
			return storedFailure(r.ID, err)
		}
		a := s.actor(r.Profile)
		if a == nil {
			a = newSupervisor(s, p)
			s.mu.Lock()
			s.actors[p.ID] = a
			s.mu.Unlock()
			go a.run()
		}
		reply := a.call(controlInput{op: "up", origin: c})
		if reply.code != "" {
			detail := reply.detail
			if detail == "" {
				detail = "profile cannot start"
			}
			return failure(r.ID, reply.code, detail)
		}
		result.Data = struct {
			Attempt uint64 `json:"attempt"`
		}{reply.status.Attempt}
	case "down":
		// A manual profile-file error must not prevent stopping an existing actor.
		if !r.All && s.actor(r.Profile) == nil {
			if _, err := s.store.Get(r.Profile); err != nil {
				return storedFailure(r.ID, err)
			}
		}
		s.mu.Lock()
		actors := make([]*supervisor, 0, len(s.actors))
		for id, a := range s.actors {
			if r.All || id == r.Profile {
				actors = append(actors, a)
			}
		}
		s.mu.Unlock()
		for _, a := range actors {
			a.call(controlInput{op: "down"})
		}
	case "answer", "cancel":
		s.mu.Lock()
		route := s.challenges[r.ChallengeID]
		s.mu.Unlock()
		if route == nil {
			return failure(r.ID, protocol.NotFound, "challenge is no longer pending")
		}
		reply := route.actor.call(controlInput{op: r.Op, challengeID: r.ChallengeID, secret: []byte(r.Secret)})
		if reply.code != "" {
			return failure(r.ID, reply.code, "challenge is no longer pending")
		}
	case "trust":
		a := s.actor(r.Profile)
		if a == nil {
			return failure(r.ID, protocol.Conflict, "no rejected certificate to trust")
		}
		reply := a.call(controlInput{op: "trust", digest: r.Digest})
		if reply.code != "" {
			return failure(r.ID, reply.code, "certificate cannot be trusted")
		}
	case "logs":
		if _, err := s.store.Get(r.Profile); err != nil {
			return storedFailure(r.ID, err)
		}
		lines := r.Lines
		if lines == 0 {
			lines = 100
		}
		logs, err := readLogsAt(s.logDir, r.Profile, lines)
		if err != nil {
			return failure(r.ID, protocol.Internal, "logs unavailable")
		}
		result.Data = logs
		// Keep the newest diagnostics, accounting for JSON escaping and the envelope.
		for len(logs) > 0 {
			data, err := json.Marshal(result)
			if err != nil || len(data)+1 <= protocol.MaxLine {
				break
			}
			logs = logs[1:]
			result.Data = logs
		}
	default:
		return failure(r.ID, protocol.Invalid, "unknown operation")
	}
	// Aggregate responses are bounded just like requests; never partially stream a list.
	data, err := json.Marshal(result)
	if err != nil || len(data)+1 > protocol.MaxLine {
		return failure(r.ID, protocol.Busy, "result exceeds record limit")
	}
	return result
}
