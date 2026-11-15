import { SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY } from "./config.js";
import { sessionExpired } from "./validate.js";

// Sessions live in sessionStorage, so closing the browser tab ends them.
export const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
  auth: { storage: window.sessionStorage, persistSession: true, autoRefreshToken: true, detectSessionInUrl: false },
});

export async function currentStaff() {
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) return null;
  if (sessionExpired(sessionStorage.getItem("dr_signed_in_at"))) {
    await supabase.auth.signOut({ scope: "local" });
    return null;
  }
  const { data, error } = await supabase.from("staff").select("user_id").eq("user_id", session.user.id).maybeSingle();
  if (error || !data) return null;
  return session.user;
}
