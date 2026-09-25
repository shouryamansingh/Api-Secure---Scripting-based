import {
  signInWithPopup,
  signInWithEmailAndPassword,
  EmailAuthProvider,
  linkWithCredential,
  updateProfile,
} from "firebase/auth";
import { auth, googleProvider } from "./firebase";
import { supabase } from "./supabase";
import { getUserProfile, saveUserProfile, updateLastLogin } from "../utils/userProfile";

/**
 * Google sign-in with Supabase integration
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
    } catch (supabaseError) {
      console.warn("Supabase error, treating as new user:", supabaseError);
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

/**
 * Complete profile setup for new Google users
 */
export const completeProfileSetup = async (userId, username, email, password, displayName, photoURL) => {
  try {
    const trimmedEmail = email.trim();
    const currentUser = auth.currentUser;

    if (!currentUser) {
      return { success: false, error: "Authentication session expired. Please try again." };
    }

    // Link email/password credential to Google account
    try {
      const credential = EmailAuthProvider.credential(trimmedEmail, password);
      await linkWithCredential(currentUser, credential);
    } catch (linkError) {
      if (
        linkError.code !== "auth/provider-already-linked" &&
        linkError.code !== "auth/email-already-in-use"
      ) {
        console.warn("Could not link email/password:", linkError.message);
      }
    }

    // Save to Supabase
    const result = await saveUserProfile(userId, trimmedEmail, username, displayName, photoURL, trimmedEmail);

    if (!result.success) {
      return { success: false, error: result.error || "Failed to save profile" };
    }

    // Update Firebase display name + photo
    try {
      await updateProfile(currentUser, { displayName: username, photoURL: photoURL || null });
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

    // If username (no @), look up email from Supabase
    if (!email.includes("@")) {
      const { data, error } = await supabase
        .from("users")
        .select("email")
        .eq("username", email)
        .single();

      if (error || !data) {
        return { success: false, error: "Username not found" };
      }
      email = data.email;
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
