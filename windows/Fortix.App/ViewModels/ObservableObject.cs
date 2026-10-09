using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;

namespace Fortix.App.ViewModels;

/// <summary>
/// Base for bindable objects: raises <see cref="PropertyChanged"/> only for real changes.
/// </summary>
public abstract class ObservableObject : INotifyPropertyChanged
{
    /// <inheritdoc/>
    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>
    /// Stores a new value and notifies when it differs from the old one.
    /// </summary>
    /// <typeparam name="T">The property type.</typeparam>
    /// <param name="field">The backing field.</param>
    /// <param name="value">The new value.</param>
    /// <param name="name">The property name, supplied by the compiler.</param>
    /// <returns>True when the value changed.</returns>
    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }
        field = value;
        OnPropertyChanged(name);
        return true;
    }

    /// <summary>
    /// Raises <see cref="PropertyChanged"/> for one property, or for all when the name is null.
    /// </summary>
    /// <param name="name">The property name.</param>
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>
/// A command that runs a delegate and whose availability is re-evaluated on request.
/// </summary>
public sealed class RelayCommand : ICommand
{
    /// <summary>The action, given the binding's command parameter.</summary>
    private readonly Action<object?> execute;

    /// <summary>The availability check, or null for always available.</summary>
    private readonly Func<object?, bool>? canExecute;

    /// <summary>
    /// Creates the command.
    /// </summary>
    /// <param name="execute">The action.</param>
    /// <param name="canExecute">The availability check.</param>
    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    {
        ArgumentNullException.ThrowIfNull(execute);
        this.execute = execute;
        this.canExecute = canExecute;
    }

    /// <inheritdoc/>
    public event EventHandler? CanExecuteChanged;

    /// <inheritdoc/>
    public bool CanExecute(object? parameter) => canExecute?.Invoke(parameter) ?? true;

    /// <inheritdoc/>
    public void Execute(object? parameter)
    {
        if (CanExecute(parameter))
        {
            execute(parameter);
        }
    }

    /// <summary>
    /// Tells bound controls to ask <see cref="CanExecute"/> again.
    /// </summary>
    public void Refresh() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}
