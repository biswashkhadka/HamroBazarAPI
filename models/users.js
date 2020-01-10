const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    fullname: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true,
    },
    phone: {
        type: String,
        maxlength:8,
    },
    mobilephone: {
        type: String,
        required: true,
        maxlength:10
    },
    address1: {
        type: String,
        required: true,
    },
    address2: {
        type: String,
        required: true,
    },
    address3: {
        type: String,
        required: true,
    },
    image: {
        type: String
    },
    admin: {
        type: Boolean,
        default: false
    }
});

module.exports = mongoose.model('', userSchema);