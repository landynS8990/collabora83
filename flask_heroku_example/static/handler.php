

<?php
   $to_email = "jadenbh12@gmail.com";
   $subject = "Simple Email Test via PHP";
   $body = "Hope to god this fucking works";
   $headers = "From: Projec";
 
   if ( mail($to_email, $subject, $body, $headers)) {
      echo("Email successfully sent to $to_email...");
   } else {
      echo("Email sending failed...");
   }
?>