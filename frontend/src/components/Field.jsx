/** Labelled input with an inline error message (wired to aria-describedby for screen readers). */
export default function Field({ id, label, error, hint, ...inputProps }) {
  const describedBy = error ? `${id}-error` : hint ? `${id}-hint` : undefined;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input id={id} name={id} aria-invalid={Boolean(error)} aria-describedby={describedBy} {...inputProps} />
      {hint && !error && <span id={`${id}-hint`} className="field-hint">{hint}</span>}
      {error && <span id={`${id}-error`} className="field-error">{error}</span>}
    </div>
  );
}

export const PASSWORD_HINT = 'At least 8 characters, with at least one letter and one number.';

/** Same rule as the backend's @StrongPassword, checked early for faster feedback. */
export function passwordProblem(password) {
  if (password.length < 8 || password.length > 72) return 'Password must be 8 to 72 characters long';
  if (!/[A-Za-z]/.test(password) || !/\d/.test(password)) return 'Password must contain at least one letter and one number';
  return null;
}
