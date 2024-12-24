<?php

class Visitor 
{
    private $id;
    private $cookie_status = '';

    public function __construct(string $ip, string $user_agent)
    {
        $hash = $this->calculate_hash($ip, $user_agent);
        
            setcookie('u_ha', $hash, [
                'expires' => time() + 2592000,
                'path' => '/',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Lax'
            ]);
            $this->cookie_status = "cookie set";
    }

    private function calculate_hash(string $ip, string $user_agent) : string
    {
        $salt = self::visitor_token_salt();
        $result = $salt . $ip . $user_agent;
        return md5($result);
    }

    public function get_cookie_status() : string
    {
        return $this->cookie_status;
    }

    public static function fetch_current_visitor() : self
    {
        return new self($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT']);
    }

    // Salt-related methods
    private static function visitor_token_salt() : string
    {
        return self::get_salt_option('iawp_salt');
    }

    private static function refresh_visitor_token_salt() : string
    {
        \delete_option('iawp_salt');
        return self::get_salt_option('iawp_salt');
    }

    private static function get_salt_option($name) : string
    {
        $salt = \get_option($name);
        if (!$salt) {
            $salt = self::generate_salt();
            \update_option($name, $salt, \true);
        }
        return $salt;
    }

    private static function generate_salt() : string
    {
        $length = 32;
        $bytes = \random_bytes($length);
        return \substr(\strtr(\base64_encode($bytes), '+', '.'), 0, 44);
    }
}

$visitor = Visitor::fetch_current_visitor();
//echo $visitor->get_cookie_status(); // Will output "cookie set" if IP matches
