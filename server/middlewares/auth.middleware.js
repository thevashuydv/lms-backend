import jwt from 'jsonwebtoken';
import AppError from '../utils/error.util.js';

const isLoggedIn = async (req, res, next) => {
    const { token } = req.cookies;

    if (!token) {
        return next(new AppError('Unauthenticated, please login again', 400));
    }

    try {
        const userDetails = await jwt.verify(token, process.env.JWT_SECRET);
        req.user = userDetails;
        next();
    } catch (error) {
        return next(new AppError('Token is not valid', 401));
    }
};

const authorizedRoles = (...roles) => (req, res, next) => {
    const currentUserRole = req.user.role;

    if (!roles.includes(currentUserRole)) {
        return next(new AppError('You don\'t have permission', 403));
    }

    next();
};

const authorizeSubscriber =async (req, res,next) => {
       const subscription = req.user.subscription;
       const currentUserRole = req.user.role;
       if( currentUserRole!== 'ADMIN' && subscription!== 'active'){
           return next(
            new AppError('Please subscribe to access this route!', 403)
           )
       }
}

export {
    isLoggedIn,
    authorizedRoles,
    authorizeSubscriber
};
