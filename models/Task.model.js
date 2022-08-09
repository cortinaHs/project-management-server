const mongoose = require('mongoose');
const { Schema, model } = mongoose;
 
const taskSchema = new Schema({
  title: String,
  description: String,
  done: {
    type: Boolean,
    default: false
  },
  project: { type: Schema.Types.ObjectId, ref: 'Project' }
});
 
module.exports = model('Task', taskSchema);