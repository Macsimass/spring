package org.example.entity;

import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;
import lombok.Data;


public record RestBean<T> (int code, T data, String message){
    public static <T> RestBean<T> success(T data) {
        System.out.println(data);
        return new RestBean<>(200, data, "success");
    }
    public static <T> RestBean<T> failure(int code, String message) {
        return new RestBean<>(code, null, message);
    }
    public static <T> RestBean<T> failure(int code) {
        return failure(code, "failure");
    }
    public String asJsonObject() {
        return JSONObject.toJSONString(this, JSONWriter.Feature.WriteNulls);
    }
}
