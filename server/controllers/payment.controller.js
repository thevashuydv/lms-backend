import { razorpay } from "../server.js";
import AppError from "../utils/error.util.js";
import crypto from 'crypto';


export const getRazorpayApiKey = async (req,res, next)  => {

    res.status(200).json({
        success: true,
        message: 'Razorpay API Key',
        key: process.env.RAZORPAY_KEY_ID
    });
    
}
export const buySubscription = async (req,res, next)  => {

    const {}  =req.user;
    const user = await User.findById(id);

    if(!user){
        return next(
            new AppError('Unauthorized, please login',500)
        )
    }

    if(user.role === 'ADMIN'){
        return next(
            new AppError('Admin cannot purchase a subscription',500)
        )
    }

    const subscription = await razorpay.subscriptions.create({
        plan_id: process.env.RAZORPAY_PLAN_ID,
        customer_notify: 1
    });

    user.subscription.id = subscription.id;
    user.subscription.status = subscription.status;

    await user.save();

    res.status(200).json({
        success: true,
        message: 'Subscribed Successfully',
        subscription_id : subscription.id  
    });


}
export const verifySubscription = async (req,res, next)  => {

    const {id} = req.user;

    const { razorpay_payment_id, razorpay_signature, razorpay_subscription_id } = req.body;

    const user = await User.findById(id);

    if(!user){
        return next(
            new AppError('Unauthorized, please login', 500)
        )
    }

    const subscriptionId = user.subscription.id;

    const generatedSignature = crypto
         .createHmac('sha256', process.env.RAZORPAY_SECRET)
         .update(`${razorpay_payment_id}|${subscriptionId}`)
         .digest('hex');

    if(generatedSignature !== razorpay_signature){
        return next(
            new AppError('Payment not verify, try again', 500)
        )
    }

    await Payment.create({
        razorpay_payment_id,
        razorpay_signature,
        razorpay_subscription_id,
    });

    user.subscription.status = 'active';
    await user.save();

    res.status(200).json({
        success: true,
        message: 'Payment verified Successfully',
          
    });

}
export const cancelSubscription = async (req,res, next)  => {

    const {id} = req.user;
    const user = await User.findById(id);

    if(!user){
        return next(
            new AppError('Unauthorized, please login',500)
        )
    }

    if(user.role === 'ADMIN'){
        return next(
            new AppError('Admin cannot cancel a subscription',500)
        )
    }

    const subscriptionId = user.subscription.id;

    const subscription = await razorpay.subscriptions.cancel(
        subscriptionId
    )

    user.subscription.status = subscription.status;

    await user.save();

}
export const allPayments = async (req,res, next)  => {

    const {count} = req.query;

    const subscriptions = await razorpay.subscriptions.all({
        count: count || 10,
    });

    res.status(200).json({
        success: true,
        message: 'All payments',
        subscriptions
          
    });


    

}


