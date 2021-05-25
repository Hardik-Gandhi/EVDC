module.exports = {
    dbUrl: process.env.NODE_ENV == "development" ? "mongodb://127.0.0.1:27017/evdc" : process.env.MONGODB_URI,
    jwtSecretKey: process.env.JWT_SECRETKEY,
    gst: process.env.gst,
    commission: process.env.commission,
    GOOGLE_CLIENTID : process.env.GOOGLE_CLIENTID,
    GOOGLE_SECRETKEY : process.env.GOOGLE_SECRETKEY,
    GOOGLE_CALLBACK : process.env.GOOGLE_CALLBACK,
    FACEBOOK_APPID : process.env.FACEBOOK_APPID,
    FACEBOOK_SECRET : process.env.FACEBOOK_SECRET,
    FACEBOOK_CALLBACK : process.env.FACEBOOK_CALLBACK
}