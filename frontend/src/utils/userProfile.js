import { doc, getDoc, updateDoc, runTransaction } from "firebase/firestore";
import { db } from "../lib/firebase";

/*
 * Firestore layout:
 *   users/{uid}             profile (username, email, Google details, timestamps)
 *   usernames/{lowercase}   { uid, email } — reserves a username and lets the
 *                           login form turn a username into an email
 */
const userRef = (uid) => doc(db, "users", uid);
const usernameRef = (username) => doc(db, "usernames", username.trim().toLowerCase());

const firestoreErrorMessage = (error, fallback) => {
  switch (error?.code) {
    case "permission-denied":
      return "Firebase blocked access to your profile. Check the Firestore security rules (see SETUP.md).";
    case "not-found":
    case "failed-precondition":
      return "The Firestore database isn't set up yet. Create it in Firebase Console → Firestore Database (see SETUP.md).";
    case "unavailable":
      return "Can't reach Firebase right now. Check your connection and try again.";
    default:
      return error?.message || fallback;
  }
};

/**
 * Get user profile. Throws when Firestore can't be reached, so callers can
 * tell "no profile yet" (null) apart from "couldn't check".
 */
export async function fetchUserProfileStrict(uid) {
  const snap = await getDoc(userRef(uid));
  return snap.exists() ? snap.data() : null;
}

/**
 * Get user profile, or null if it doesn't exist or can't be loaded.
 */
export async function getUserProfile(uid) {
  try {
    return await fetchUserProfileStrict(uid);
  } catch (error) {
    console.error("Error fetching user profile:", error);
    return null;
  }
}

/**
 * Save or update user profile. The username is reserved in the same
 * transaction, so two accounts can never end up with the same username.
 */
export async function saveUserProfile(
  uid,
  email,
  username,
  googleDisplayName,
  googlePhotoUrl,
  googleEmail
) {
  const trimmedEmail = email.trim();
  const trimmedUsername = username.trim();
  const usernameKey = trimmedUsername.toLowerCase();
  const trimmedGoogleEmail = googleEmail?.trim();

  try {
    await runTransaction(db, async (tx) => {
      const [userSnap, nameSnap] = await Promise.all([
        tx.get(userRef(uid)),
        tx.get(usernameRef(usernameKey)),
      ]);

      if (nameSnap.exists() && nameSnap.data().uid !== uid) {
        throw Object.assign(new Error("Username taken"), { code: "app/username-taken" });
      }

      const previous = userSnap.exists() ? userSnap.data() : null;
      if (previous?.usernameLower && previous.usernameLower !== usernameKey) {
        tx.delete(usernameRef(previous.usernameLower));
      }

      const now = new Date().toISOString();
      const profileData = {
        id: uid,
        email: trimmedEmail,
        username: trimmedUsername,
        usernameLower: usernameKey,
        google_connected: !!googleEmail,
        has_password: true,
        last_login: now,
      };
      if (!previous) profileData.created_at = now;
      if (googleDisplayName) profileData.google_display_name = googleDisplayName;
      if (googlePhotoUrl) profileData.google_photo_url = googlePhotoUrl;
      if (trimmedGoogleEmail) profileData.google_email = trimmedGoogleEmail;

      tx.set(usernameRef(usernameKey), { uid, email: trimmedEmail });
      tx.set(userRef(uid), profileData, { merge: true });
    });
    return { success: true };
  } catch (error) {
    if (error.code === "app/username-taken") {
      return { success: false, error: "This username is already taken." };
    }
    console.error("Error saving user profile:", error);
    return { success: false, error: firestoreErrorMessage(error, "Failed to save profile") };
  }
}

/**
 * Update last login timestamp
 */
export async function updateLastLogin(uid) {
  try {
    await updateDoc(userRef(uid), { last_login: new Date().toISOString() });
  } catch (error) {
    console.error("Error updating last login:", error);
  }
}

/**
 * Check if username is available. Returns true/false, or null when it
 * couldn't be checked (the save transaction still enforces uniqueness).
 */
export async function isUsernameAvailable(username, excludeUid) {
  try {
    const snap = await getDoc(usernameRef(username));
    return !snap.exists() || (!!excludeUid && snap.data().uid === excludeUid);
  } catch (error) {
    console.error("Error checking username:", error);
    return null;
  }
}

/**
 * Look up the email registered for a username (used by username login).
 */
export async function getEmailForUsername(username) {
  const snap = await getDoc(usernameRef(username));
  return snap.exists() ? snap.data().email || null : null;
}
