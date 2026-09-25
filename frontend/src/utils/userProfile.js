import { supabase } from "../lib/supabase";

/**
 * Get user profile from Supabase
 */
export async function getUserProfile(uid) {
  try {
    const { data, error } = await supabase
      .from("users")
      .select("*")
      .eq("id", uid)
      .single();

    if (error) {
      if (error.code === "PGRST116") {
        return null;
      }
      throw error;
    }

    return data;
  } catch (error) {
    console.error("Error fetching user profile:", error);
    return null;
  }
}

/**
 * Save or update user profile in Supabase
 */
export async function saveUserProfile(
  uid,
  email,
  username,
  googleDisplayName,
  googlePhotoUrl,
  googleEmail
) {
  try {
    const trimmedEmail = email.trim();
    const trimmedUsername = username.trim();
    const trimmedGoogleEmail = googleEmail?.trim();

    // Check if user already exists
    const { data: existingUser, error: checkError } = await supabase
      .from("users")
      .select("*")
      .or(`id.eq.${uid},email.eq.${trimmedEmail}`)
      .maybeSingle();

    if (checkError && checkError.code !== "PGRST116") {
      return { success: false, error: checkError.message || "Failed to check existing user" };
    }

    const profileData = {
      id: uid,
      email: trimmedEmail,
      username: trimmedUsername,
      google_connected: !!googleEmail,
      has_password: true,
      last_login: new Date().toISOString(),
    };

    if (googleDisplayName) profileData.google_display_name = googleDisplayName;
    if (googlePhotoUrl) profileData.google_photo_url = googlePhotoUrl;
    if (trimmedGoogleEmail) profileData.google_email = trimmedGoogleEmail;

    let result;

    if (existingUser) {
      result = await supabase.from("users").update(profileData).eq("id", uid);
    } else {
      profileData.created_at = new Date().toISOString();
      result = await supabase.from("users").insert([profileData]);
    }

    if (result.error) {
      if (result.error.code === "23505") {
        if (result.error.message.includes("users_email_key")) {
          return { success: false, error: "This email is already registered." };
        }
        if (result.error.message.includes("users_username_key")) {
          return { success: false, error: "This username is already taken." };
        }
      }
      return { success: false, error: result.error.message || "Failed to save profile" };
    }

    return { success: true };
  } catch (error) {
    return { success: false, error: error.message || "Failed to save profile" };
  }
}

/**
 * Update last login timestamp
 */
export async function updateLastLogin(uid) {
  try {
    await supabase
      .from("users")
      .update({ last_login: new Date().toISOString() })
      .eq("id", uid);
  } catch (error) {
    console.error("Error updating last login:", error);
  }
}

/**
 * Check if username is available
 */
export async function isUsernameAvailable(username, excludeUid) {
  try {
    let query = supabase.from("users").select("id").eq("username", username);
    if (excludeUid) {
      query = query.neq("id", excludeUid);
    }
    const { data, error } = await query;
    if (error) throw error;
    return !data || data.length === 0;
  } catch (error) {
    console.error("Error checking username:", error);
    return false;
  }
}
