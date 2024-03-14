const express = require("express");
const router = express.Router();
const contactsController = require("../../controllers/contactsController");
const { protectRoute } = require("../../middleware/authMiddleware");

router.use(protectRoute);

router.get("/", contactsController.getAllContacts);
router.post("/", contactsController.createContact);
router.put("/:id", contactsController.updateContact);
router.delete("/:id", contactsController.deleteContact);
router.patch("/:id/favorite", contactsController.updateStatusContact);

// Ruta pentru paginarea contactelor
router.get("/paginated", contactsController.getPaginatedContacts);

// Ruta pentru filtrarea contactelor după câmpul favorite
router.get("/filtered", contactsController.getFilteredContacts);
module.exports = router;
