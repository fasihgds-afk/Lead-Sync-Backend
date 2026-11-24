const bcrypt = require("bcryptjs");
const User = require("../models/User");

function getSaltRounds() {
  const rounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || "10", 10);
  if (!rounds || isNaN(rounds)) return 10;
  if (rounds < 8) return 10;
  if (rounds > 14) return 12;
  return rounds;
}

module.exports = async function bootstrapSuperAdmin() {
  const email = process.env.SUPER_ADMIN_EMAIL;
  const password = process.env.SUPER_ADMIN_PASSWORD;
  const name = process.env.SUPER_ADMIN_NAME || "Initial Super Admin";

  if (!email || !password) {
    console.log("SUPER_ADMIN_EMAIL / SUPER_ADMIN_PASSWORD missing. Skipping bootstrap.");
    return;
  }

  // Check if any Super Admin already exists
  const existingSuper = await User.findOne({ role: "Super Admin", status: "APPROVED" });
  
  if (existingSuper) {
    let needsUpdate = false;

    // Verify if the environment password matches the existing hash
    const isPasswordMatch = await bcrypt.compare(String(password), existingSuper.passwordHash);
    if (!isPasswordMatch) {
      existingSuper.passwordHash = await bcrypt.hash(String(password), getSaltRounds());
      needsUpdate = true;
    }

    // Optional: Keep email synchronized with .env if it was changed there
    if (existingSuper.email !== String(email).toLowerCase()) {
      existingSuper.email = String(email).toLowerCase();
      needsUpdate = true;
    }

    if (needsUpdate) {
      await existingSuper.save();
      console.log("Super admin credentials updated successfully from environment variables.");
    } else {
      console.log("Super admin already exists and credentials match. Skipping.");
    }
    return;
  }

  // if user exists with same email, promote it
  const existingEmail = await User.findOne({ email: String(email).toLowerCase() });
  if (existingEmail) {
    existingEmail.role = "Super Admin";
    existingEmail.status = "APPROVED";
    existingEmail.approvedAt = new Date();
    existingEmail.passwordHash = await bcrypt.hash(String(password), getSaltRounds());
    await existingEmail.save();
    console.log("Existing user promoted to Super Admin:", email);
    return;
  }

  // Otherwise, create the super admin from scratch
  const passwordHash = await bcrypt.hash(String(password), getSaltRounds());

  await User.create({
    name: name,
    email: String(email).toLowerCase(),
    sex: "male",
    role: "Super Admin",
    status: "APPROVED",
    passwordHash: passwordHash,
    profileImage: { url: "", publicId: "" }
  });

  console.log("Bootstrap Super Admin created:", email);
};