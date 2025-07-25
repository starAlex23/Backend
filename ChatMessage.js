const mongoose = require("mongoose");

const ChatMessageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "Mitarbeiter" },
  empfänger: { type: mongoose.Schema.Types.ObjectId, ref: "Mitarbeiter" },
  text: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model("ChatMessage", ChatMessageSchema);
