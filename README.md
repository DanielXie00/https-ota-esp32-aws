# https-ota-esp32-aws

Uses an mbedTLS socket to make a very simple HTTPS request over a secure connection, including verifying the server TLS certificate.

   Step 1 : you have to create an Amazon S3 account
   
   Step 2 : Download the sample bin file from the examples folder
   
   Step 3 : Upload it to your Amazon S3 account, in a bucket of your choice
   
   Step 4 : Once uploaded, inside S3, select the bin file >> More (button on top of the file list) >> Make Public
   
  Step 5 : You S3 URL => https://s3-us-west-2.amazonaws.com/Your-account/test_ota.bin
   
   Step 6 : Build the above URL and fire it either in your browser  to validate the URL
   
   Step 7:  Plug in your SSID, Password, S3 Host and Bin file below
   
   step 8:  Checking certificates on Firefox.and save it to "server_root_cert.pem"


NOTE:

  1.Download the code 
  
  2.Cd to source，make menuconfig ->Example Configguration -->wifi ssid and wifi password
     Partition Table -->Factory app,two OTA definitions.https://github.com/DanielXie00/https-ota-esp32-aws/tree/master/STEPS

   3.build and download.
