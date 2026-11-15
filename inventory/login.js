import { supabase, currentStaff } from "./client.js";
import { loginThrottle } from "./validate.js";

const form = document.querySelector("#login");
const error = document.querySelector("#login-error");
const button = document.querySelector("#submit");

if (await currentStaff()) location.replace("../");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  error.textContent = "";
  const throttle = loginThrottle(localStorage);
  if (throttle.locked) {
    error.textContent = "Too many failed sign-ins. Wait 15 minutes and try again.";
    return;
  }
  const email = form.email.value.trim();
  const password = form.password.value;
  if (!email || !password || password.length > 200) {
    error.textContent = "Enter the email and password for the inventory account.";
    return;
  }
  button.disabled = true;
  try {
    const { data, error: authError } = await supabase.auth.signInWithPassword({ email, password });
    if (authError || !data.session) {
      throttle.fail();
      error.textContent = authError && authError.status === 429
        ? "Too many sign-in attempts. Wait a few minutes and try again."
        : "That email and password did not match an inventory account.";
      return;
    }
    sessionStorage.setItem("dr_signed_in_at", String(Date.now()));
    const staff = await currentStaff();
    if (!staff) {
      await supabase.auth.signOut({ scope: "local" });
      throttle.fail();
      error.textContent = "That account is not allowed to use inventory entry.";
      return;
    }
    throttle.clear();
    // A new sign-in replaces any earlier session for this account.
    await supabase.auth.signOut({ scope: "others" });
    location.replace("../");
  } finally {
    form.password.value = "";
    button.disabled = false;
  }
});
