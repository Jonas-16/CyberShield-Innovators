const CURRENT_USER_KEY = 'cybershieldCurrentUser';
const DEVICE_ID_KEY = 'cybershieldDeviceId';

function safeParse(value, fallback) {
  try {
    return JSON.parse(value) || fallback;
  } catch (_) {
    return fallback;
  }
}

export function makeUserId(email) {
  return String(email || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'guest';
}

export function loadCurrentUser() {
  const user = safeParse(localStorage.getItem(CURRENT_USER_KEY), null);
  if (!user || !user.id || user.password) {
    localStorage.removeItem(CURRENT_USER_KEY);
    return null;
  }
  return user;
}

export function saveCurrentUser(user) {
  localStorage.setItem(CURRENT_USER_KEY, JSON.stringify(user));
}

export function clearCurrentUser() {
  localStorage.removeItem(CURRENT_USER_KEY);
}

export function scopedKey(baseKey, userId) {
  return `${baseKey}:${userId || 'guest'}`;
}

export function localDeviceId() {
  let deviceId = localStorage.getItem(DEVICE_ID_KEY);
  if (!deviceId) {
    const uuid = globalThis.crypto?.randomUUID?.()
      || `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
    deviceId = `browser-${uuid}`;
    localStorage.setItem(DEVICE_ID_KEY, deviceId);
  }
  return deviceId;
}
