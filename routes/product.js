const express = require('express');
const Listed = require('../models/product');

const router = express.Router();

router.post('/addListedads', (req, res, next) => {
    
        Listed.create({
            adName:req.body.adName,
            Adprice:req.body.Adprice,
            Producttype:req.body.Producttype,
            image: req.body.image
        }).then((listed) => {
            res.json({ status: "lited ads add success!" });
        }).catch(next);
    })

router.get('/',(req, res, next) => {
    Listed.find({},(err,listedads)=>{
        if(err){
            res.json(next)
        }
        res.json(listedads)
    });
})
        
module.exports = router;
