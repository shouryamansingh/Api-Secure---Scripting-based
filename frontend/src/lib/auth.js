import {
  signInWithPopup,
  signInWithEmailAndPassword,
  EmailAuthProvider,
  linkWithCredential,
  updatePassword,
  updateProfile,
} from "firebase/auth";
import { auth, googleProvider } from "./firebase";
import {
  getUserProfile,
  saveUserProfile,
  updateLastLogin,
  isUsernameAvailable,
  getEmailForUsername,
} from "../utils/userProfile";

/**
 * Google sign-in; profiles live in Firestore
 */
export const signInWithGoogleSimple = async () => {
  try {
    const result = await signInWithPopup(auth, googleProvider);
    const user = result.user;

    try {
      const userProfile = await getUserProfile(user.uid);

      if (!userProfile) {
        // New user — needs profile setup
        return { success: true, user, isNewUser: true, userData: null };
      } else {
        // Existing user — update last login
        await updateLastLogin(user.uid);

        if (userProfile.google_photo_url && user.photoURL !== userProfile.google_photo_url) {
          try {
            await updateProfile(user, { photoURL: userProfile.google_photo_url });
          } catch (_) {}
        }

        return { success: true, user, isNewUser: false, userData: userProfile };
      }
    } catch (profileError) {
      console.warn("Profile lookup failed, treating as new user:", profileError);
      return { success: true, user, isNewUser: true, userData: null, offline: true };
    }
  } catch (error) {
    console.error("Google sign-in failed:", error.code, error.message);
    let errorMessage = `Failed to sign in with Google. (${error.code || "unknown error"})`;
    switch (error.code) {
      case "auth/popup-closed-by-user":
        errorMessage = "Sign-in popup was closed. Please try again.";
        break;
      case "auth/cancelled-popup-request":
        errorMessage = "Sign-in was cancelled. Please try again.";
        break;
      case "auth/popup-blocked":
        errorMessage = "Sign-in popup was blocked. Please allow popups for this site.";
        break;
      case "auth/configuration-not-found":
      case "auth/operation-not-allowed":
        errorMessage =
          "Google sign-in is not enabled for this Firebase project. Enable Authentication → Google in the Firebase Console.";
        break;
      case "auth/unauthorized-domain":
        errorMessage =
          "This domain is not authorized for sign-in. Add it under Authentication → Settings → Authorized domains.";
        break;
      case "auth/invalid-api-key":
      case "auth/api-key-not-valid":
        errorMessage = "The Firebase API key is invalid. Check VITE_FIREBASE_API_KEY in frontend/.env.";
        break;
      case "auth/network-request-failed":
        errorMessage = "Network error reaching Firebase. Check your connection and try again.";
        break;
    }
    return { success: false, error: errorMessage };
  }
};

/** True when the Firebase user can already sign in with a password. */
export const hasPasswordProvider = (user) =>
  !!user?.providerData?.some((p) => p.providerId === "password");

// No "@" allowed: the login form treats any input containing "@" as an email.
const USERNAME_PATTERN = /^[A-Za-z0-9_.]+$/;

/** Returns an error message, or "" when the username is valid. */
export const validateUsername = (username) => {
  const u = (username || "").trim();
  if (!u) return "Choose a username.";
  if (u.length < 3 || u.length > 20) return "Username must be 3–20 characters.";
  if (!USERNAME_PATTERN.test(u)) return "Use only letters, numbers, dots (.) and underscores (_).";
  return "";
};

/** Password rules shown as a live checklist; all must pass. */
export const getPasswordChecks = (password, { username = "", email = "" } = {}) => {
  const pw = password || "";
  const lower = pw.toLowerCase();
  const personal = [username, (email || "").split("@")[0]]
    .map((s) => (s || "").trim().toLowerCase())
    .filter((s) => s.length >= 3);
  return [
    { id: "length", label: "At least 8 characters", ok: pw.length >= 8 },
    { id: "upper", label: "An uppercase letter (A–Z)", ok: /[A-Z]/.test(pw) },
    { id: "lower", label: "A lowercase letter (a–z)", ok: /[a-z]/.test(pw) },
    { id: "number", label: "A number (0–9)", ok: /\d/.test(pw) },
    { id: "symbol", label: "A symbol (e.g. ! @ # $ %)", ok: /[^A-Za-z0-9\s]/.test(pw) },
    {
      id: "personal",
      label: "Doesn't contain your username or email",
      ok: pw.length > 0 && !personal.some((p) => lower.includes(p)),
    },
  ];
};

const passwordSetupError = (err) => {
  switch (err?.code) {
    case "auth/operation-not-allowed":
      return "Password sign-in isn't enabled for this app yet. In Firebase Console → Authentication → Sign-in method, enable Email/Password, then try again.";
    case "auth/weak-password":
    case "auth/password-does-not-meet-requirements":
      return "That password is too weak. Please choose a stronger one.";
    case "auth/requires-recent-login":
      return "For your security, please sign in with Google again, then set your password.";
    case "auth/email-already-in-use":
    case "auth/credential-already-in-use":
      return "This email already has a separate password account. Sign in with that password instead.";
    case "auth/network-request-failed":
      return "Network error. Check your connection and try again.";
    default:
      return `Couldn't set your password (${err?.code || "unknown error"}). Please try again.`;
  }
};

/**
 * Complete profile setup for new Google users.
 * The password is attached to the Google account first; the profile is saved
 * only if that succeeds, so an account is never marked as having a password
 * it can't actually sign in with. Safe to retry after a partial failure.
 */
export const completeProfileSetup = async (userId, username, email, password, displayName, photoURL) => {
  try {
    const currentUser = auth.currentUser;
    if (!currentUser || currentUser.uid !== userId) {
      return { success: false, error: "Your sign-in session expired. Please sign in with Google again." };
    }

    const trimmedEmail = (email || currentUser.email || "").trim();
    const trimmedUsername = (username || "").trim();
    if (!trimmedEmail) {
      return { success: false, error: "Your Google account has no email address, so a password can't be added." };
    }

    const usernameError = validateUsername(trimmedUsername);
    if (usernameError) return { success: false, error: usernameError };

    const failed = getPasswordChecks(password, { username: trimmedUsername, email: trimmedEmail }).filter((c) => !c.ok);
    if (failed.length) {
      return { success: false, error: `Password needs: ${failed.map((c) => c.label.toLowerCase()).join(", ")}.` };
    }

    if ((await isUsernameAvailable(trimmedUsername, userId)) === false) {
      return { success: false, error: "This username is already taken. Please choose another." };
    }

    try {
      if (hasPasswordProvider(currentUser)) {
        await updatePassword(currentUser, password);
      } else {
        await linkWithCredential(currentUser, EmailAuthProvider.credential(trimmedEmail, password));
      }
    } catch (linkError) {
      if (linkError.code === "auth/provider-already-linked") {
        try {
          await updatePassword(currentUser, password);
        } catch (updateError) {
          return { success: false, error: passwordSetupError(updateError) };
        }
      } else {
        console.error("Could not set password:", linkError.code, linkError.message);
        return { success: false, error: passwordSetupError(linkError) };
      }
    }

    const result = await saveUserProfile(userId, trimmedEmail, trimmedUsername, displayName, photoURL, trimmedEmail);

    if (!result.success) {
      return { success: false, error: result.error || "Failed to save profile" };
    }

    // Update Firebase display name + photo
    try {
      await updateProfile(currentUser, { displayName: trimmedUsername, photoURL: photoURL || null });
    } catch (_) {}

    return { success: true };
  } catch (error) {
    return { success: false, error: error.message || "Failed to set up profile" };
  }
};

/**
 * Sign in with email/username and password
 */
export const signInWithPassword = async (emailOrUsername, password) => {
  try {
    let email = emailOrUsername.trim();

    // If username (no @), look up its email
    if (!email.includes("@")) {
      let found = null;
      try {
        found = await getEmailForUsername(email);
      } catch (lookupError) {
        console.error("Username lookup failed:", lookupError);
        return { success: false, error: "Couldn't look up that username. Try signing in with your email instead." };
      }
      if (!found) {
        return { success: false, error: "Username not found" };
      }
      email = found;
    }

    const userCredential = await signInWithEmailAndPassword(auth, email, password);
    const user = userCredential.user;

    await updateLastLogin(user.uid);
    const userProfile = await getUserProfile(user.uid);

    if (userProfile?.google_photo_url && user.photoURL !== userProfile.google_photo_url) {
      try {
        await updateProfile(user, { photoURL: userProfile.google_photo_url });
      } catch (_) {}
    }

    return { success: true, user, userData: userProfile };
  } catch (error) {
    if (error.code === "auth/wrong-password" || error.code === "auth/invalid-credential") {
      return { success: false, error: "Entered incorrect password!" };
    }
    if (error.code === "auth/user-not-found") {
      return { success: false, error: "Account not found" };
    }
    if (error.code === "auth/invalid-email") {
      return { success: false, error: "Invalid email address" };
    }
    if (error.code === "auth/too-many-requests") {
      return { success: false, error: "Too many failed attempts. Please try again later." };
    }
    return { success: false, error: error.message || "Failed to sign in" };
  }
};

/**
 * Get current user
 */
export const getCurrentUser = () => auth.currentUser;

/**
 * Sign out
 */
export const signOut = async () => {
  try {
    await auth.signOut();
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message || "Failed to sign out" };
  }
};
