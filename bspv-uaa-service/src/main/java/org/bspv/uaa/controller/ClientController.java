package org.bspv.uaa.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/client")
public class ClientController {

    @RequestMapping(method = RequestMethod.GET)
    @ResponseBody
    public String helloWorld() {
        return "Hello client!";
    }
}
