package org.bspv.evouchers.rest;

import java.security.Principal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class DummyController {

    @RequestMapping(method = RequestMethod.GET)
    @ResponseBody
    public String helloWorld(Principal principal) {
        return principal == null ? "Hello anonymous" : "Hello " + principal.getName();
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping(value = "admin", method = RequestMethod.GET)
    @ResponseBody
    public String helloAdminOnly(Principal principal) {
        return "Hello " + principal.getName() + ". Yes you're admin !";
    }
    
    @PreAuthorize("#oauth2.hasScope('special')")
    @RequestMapping(value = "special", method = RequestMethod.GET)
    @ResponseBody
    public String helloSecret(Principal principal) {
        return "Hello  " + principal.getName() + ". You have a special oauth scope !";
    }

}