export function formatDateTime(value) {
  if (!value) return '—';
  // The API returns UTC timestamps without an offset.
  const date = new Date(value.endsWith('Z') ? value : `${value}Z`);
  return date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export const CATEGORY_LABELS = {
  FAKE_BANK: 'Fake bank',
  FAKE_EWALLET: 'Fake e-wallet',
  FAKE_DELIVERY: 'Fake delivery',
  FAKE_GOVERNMENT: 'Fake government agency',
  OTHER: 'Other',
};

export const STATUS_LABELS = { PENDING: 'Pending', APPROVED: 'Approved', REJECTED: 'Rejected', REMOVED: 'Removed' };
