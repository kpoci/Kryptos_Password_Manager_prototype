const signUpButton=document.getElementById('signUpButton');
const signInButton=document.getElementById('button');
const signInForm=document.getElementById('signin');
const signUpForm=document.getElementById('signup');

signUpButton.addEventListener('click', function() {
    window.location.href = '/register';
})
signInButton.addEventListener('click', function() {
    console.log("Sign in button clicked");
    window.location.href = '/';
})

$(document).ready(function() {
    console.log("Document is ready.");

    // Attach event handler with `.on()` from document level
    $(document).on('submit', '#keyForm', function(event) {
        event.preventDefault();  // Stop the form from submitting via GET
        console.log("Form submission event triggered.");

        var keyName = $("#keyName").val();
        console.log("Key name to be submitted:", keyName);

        $.ajax({
            url: '/button_action',
            type: 'POST',
            data: {
                button_id: 'generate_key',
                key_name: keyName
            },
            success: function(response) {
                alert('Key generated successfully!');
                $('#inputModal').modal('hide');
                console.log("Server responded with:", response);
            },
            error: function(xhr, status, error) {
                console.error("AJAX error:", xhr.responseText);
                alert('Error generating key: ' + xhr.responseText);
            }
        });
        return false;  // Ensure no further action takes the form submission elsewhere
    });
});


