$(document).ready(function() {

    $("#signUpForm").submit(function(event) {
        // Remove the previous errors
        $(".error").text("");

        var illegalChars = /\W/; // allow letters, numbers, and underscores

        var userName = $("#username").val().trim();
        var password = $("#password").val().trim();
        var vpassword = $("#verifypassword").val().trim();
        var email = $("#email").val().trim();
        var validationFailed = false;

        /*User Name based validations*/
        if (userName.length == 0) {
            $("#errUserName").text("Username cannot be blank");
            validationFailed = true;
        } else if ((userName.length < 5) || (userName.length > 15)) {
            $("#errUserName").text("Username must be between 5 and 15 characters");
            validationFailed = true;
        } else if (illegalChars.test(userName)) {
            $("#errUserName").text("The username contains illegal characters.");
            validationFailed = true;
        }

        /*Password validations*/

        if (password != "") {
            validationFailed = passwordValidation(password, "#errPassword");
        } else {
            $("#errPassword").text("Please enter password.");
            validationFailed = true;
        }

        /*Verify Password validations*/

        if (vpassword != "") {
            validationFailed = passwordValidation(vpassword, "#errVerifyPassowrd");
        } else {
            $("#errVerifyPassowrd").text("Please verify your password.");
            validationFailed = true;
        }

        /*Passwords combined validation*/
        if (password != "" && vpassword != "" && password != vpassword) {
            $("#errVerifyPassowrd").text("Passwords must watch.");
            validationFailed = true;
        }

        /*Email validation*/
        if (email != "") {
            if (!isEmail(email)) {
                $("#errEmail").text("Invalid email id format.");
            }
        }



        if (validationFailed) {
            event.preventDefault();
        } else {
            $("#newPostForm").submit();
        }
    });

    
    $("#loginForm").submit(function(event) {
         // Remove the previous errors
        $(".error").text("");
        var userName = $("#username").val().trim();
        var password = $("#password").val().trim();
        var validationFailed = false;
        if(userName == ""){

            $("#errUserName").text("Username cannot be blank.");
            validationFailed = true;
        }

        if(password == ""){
            $("#errPassword").text("Password cannot be blank.");
            validationFailed = true;
        }

         if (validationFailed) {
            event.preventDefault();
        } else {
            $("#loginForm").submit();
        }
     });

    
});

/*Password Validations*/
    function passwordValidation(password, id) {
        if (password.length < 6) {
            $(id).text("Password must contain at least six characters.");
            return true;
        }
        if (password == $("#username").val().trim()) {
            $(id).text("Password must be different from Username.");
            return true;
        }
        re = /[0-9]/;
        if (!re.test(password)) {
            $(id).text("Password must contain at least one number (0-9).");
            return true;
        }
        re = /[a-z]/;
        if (!re.test(password)) {
            $(id).text("Password must contain at least one lowercase letter (a-z).");
            return true;
        }
        re = /[A-Z]/;
        if (!re.test(password)) {
            $(id).text("Password must contain at least one uppercase letter (A-Z).");
            return true;
        }
    }

    /*Email validation*/
    function isEmail(email) {
        var regex = /^([a-zA-Z0-9_.+-])+\@(([a-zA-Z0-9-])+\.)+([a-zA-Z0-9]{2,4})+$/;
        return regex.test(email);
    }