const mongoose = require('mongoose');

const listedadsSchema = new mongoose.Schema({
    adName: {
        type: String,
        required: true
    },
    Adprice: {
        type: String,
        required: true,
    },
    Producttype: {
        type: String,
        required: true,
    },
    image: {
        type: String
    }
});

module.exports = mongoose.model('listedads', listedadsSchema);