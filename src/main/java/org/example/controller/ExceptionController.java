package org.example.controller;

import jakarta.servlet.ServletException;
import org.example.entity.RestBean;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.NoHandlerFoundException;

@ControllerAdvice
@RestController
public class ExceptionController {
    @ExceptionHandler(Exception.class)
    public RestBean<Object> exception(Exception e) {
        if (e instanceof NoHandlerFoundException exception)
            return RestBean.failure(404, e.getMessage());
        else if(e instanceof ServletException exception)
            return RestBean.failure(400, e.getMessage());
        else return RestBean.failure(500, e.getMessage());
    }
}
