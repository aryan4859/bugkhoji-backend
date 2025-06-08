import { Router } from "express";
import { requireActiveOrganization, requireOrganizationOrAdmin } from "../middleware/auth";

const router = Router();

// Add your organization routes here

export default router;

// Example usage in routes:
router.get("/org-profile", requireActiveOrganization, (req, res) => {
  // Only active organizations can access this
})

router.get("/manage-programs", requireOrganizationOrAdmin, (req, res) => {
  // Both organizations and admins can access this
})