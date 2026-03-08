import jwt from "jsonwebtoken";

const userAuth = async (req, res, next) => {

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized. Login Again",
    });
  }

  try {
    const tokenDecoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = tokenDecoded;

    if(tokenDecoded.id){
        req.body.userId = tokenDecoded.id;
    }else{
        return res.status(401).json({
          success: false,
          message: "Unauthorized. Login Again",
        });
    }
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: error.message
    });
  }
};

export default userAuth;
