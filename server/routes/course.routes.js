import {Router} from 'express';
import { addLecturesToCourseById, createCourse, getAllCourses, getLecturesByCourseId, updateCourse,removeCourse } from '../controllers/course.controller.js';
import { isLoggedIn , authorizedRoles, authorizeSubscriber} from '../middlewares/auth.middleware.js';
import upload from '../middlewares/multer.middleware.js'

const router = Router();

router.route('/')
      .get(getAllCourses)
      .post(
        isLoggedIn,
        authorizedRoles('ADMIN'),
        upload.single('thumbnail'),
        createCourse
      );
      

router.route('/:id')
      .get(isLoggedIn,authorizeSubscriber,getLecturesByCourseId)
      .put(
        isLoggedIn,
        authorizedRoles('ADMIN'),
        updateCourse
    )
      .delete(
        isLoggedIn,
        authorizedRoles('ADMIN'),
        removeCourse
    )
    .post(
        isLoggedIn,
        authorizedRoles('ADMIN'),
        upload.single('lecture'),
        addLecturesToCourseById
    );
      



export default router;