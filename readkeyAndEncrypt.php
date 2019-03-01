<?php
    if ($argc < 2) {
        print "Usage: ".$argv[0]." <pubkey>\n";
        die();
    }
    
    function encrypt($data, $pubkey)
    {
        if (openssl_public_encrypt($data, $encrypted, $pubkey))
            $data = base64_encode($encrypted);
        else
            throw new Exception('Unable to encrypt data. Perhaps it is bigger than the key size?');
        
        return $data;
    }
    
    function decrypt($data)
    {
        if (openssl_private_decrypt(base64_decode($data), $decrypted, $this->privkey))
            $data = $decrypted;
        else
            $data = '';
        
        return $data;
    }
    
    if ($pub_key = openssl_pkey_get_public(file_get_contents($argv[1]))) {
        $keyData = openssl_pkey_get_details($pub_key);
        print "Key data:\n".var_export($keyData, true);
        print encrypt("Hello World", $pub_key);
    } else {
        print "Error reading key from ".$argv[1]."\n";
    }
    ?>
