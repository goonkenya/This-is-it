<?php
    // Define your bot token and API URL
    define('BOT_TOKEN', '7698840265:AAETvzjgHlVHqXq4yf45MvLO2SQSSJL3F78'); // **IMPORTANT: Replace with your new bot token**
    define('API_URL', 'https://api.telegram.org/bot' . BOT_TOKEN . '/');

    // Admin IDs
    $admin_ids = [6622603977];
    // VIP User IDs
    $vip = [6622603977];

    // Initialize necessary data structures
    $message_counts = [];
    $last_message_time = [];
    $time_window = 15; // seconds
    $pre_window = 10; // seconds
    $site_checking = [];
    $generated_codes = [];
    $pre_id = [];
    $r_us = [];

    // File paths
    define('REGISTERED_CHATS_FILE', 'registered_chats.txt');
    define('GENERATED_CODES_FILE', 'generated_codes.txt');

    // Ensure generated codes file exists
    if (!file_exists(GENERATED_CODES_FILE)) {
        file_put_contents(GENERATED_CODES_FILE, "");
    }

    // Helper Functions

    /**
     * Send a message via Telegram API
     */
    function sendMessage($chat_id, $text, $reply_to = null, $reply_markup = null, $parse_mode = null) {
        $url = API_URL . "sendMessage";
        $data = [
            'chat_id' => $chat_id,
            'text' => $text
        ];
        if ($reply_to !== null) {
            $data['reply_to_message_id'] = $reply_to;
        }
        if ($parse_mode !== null) {
            $data['parse_mode'] = $parse_mode;
        }
        if ($reply_markup !== null) {
            $data['reply_markup'] = json_encode($reply_markup);
        }
        // Initialize cURL
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        // Enable POST
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        // Receive server response ...
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $server_output = curl_exec($ch);
        curl_close($ch);
        return $server_output;
    }

    /**
     * Edit a message via Telegram API
     */
    function editMessage($chat_id, $message_id, $text, $reply_markup = null, $parse_mode = null) {
        $url = API_URL . "editMessageText";
        $data = [
            'chat_id' => $chat_id,
            'message_id' => $message_id,
            'text' => $text
        ];
        if ($parse_mode !== null) {
            $data['parse_mode'] = $parse_mode;
        }
        if ($reply_markup !== null) {
            $data['reply_markup'] = json_encode($reply_markup);
        }
        // Initialize cURL
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        // Enable POST
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        // Receive server response ...
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $server_output = curl_exec($ch);
        curl_close($ch);
        return $server_output;
    }

    /**
     * Generate a redeem code
     */
    function generate_redeem_code() {
        $segments = [];
        for ($i = 0; $i < 4; $i++) {
            $segments[] = substr(str_shuffle(str_repeat('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 4)), 0, 4);
        }
        return implode('-', $segments);
    }

    /**
     * Normalize URL by adding scheme if missing
     */
    function normalize_url($url) {
        // Check if the URL starts with http:// or https://
        if (!preg_match("~^(?:f|ht)tps?://~i", $url)) {
            $url = "http://" . $url;
        }
        $parsed_url = parse_url($url);
        if (!isset($parsed_url['scheme']) || !isset($parsed_url['host'])) {
            return false;
        }
        return $parsed_url['scheme'] . '://' . $parsed_url['host'];
    }

    /**
     * Read generated codes
     */
    function read_generated_codes() {
        if (!file_exists(GENERATED_CODES_FILE)) {
            file_put_contents(GENERATED_CODES_FILE, "");
        }
        $content = file_get_contents(GENERATED_CODES_FILE);
        $codes = array_filter(array_map('trim', explode("\n", $content)));
        return $codes;
    }

    /**
     * Add generated code
     */
    function add_generated_code($code) {
        file_put_contents(GENERATED_CODES_FILE, $code . "\n", FILE_APPEND | LOCK_EX);
    }

    /**
     * Remove generated code
     */
    function remove_generated_code($code) {
        $codes = read_generated_codes();
        $index = array_search($code, $codes);
        if ($index !== false) {
            unset($codes[$index]);
            file_put_contents(GENERATED_CODES_FILE, implode("\n", $codes) . "\n", LOCK_EX);
        }
    }

    /**
     * Find payment gateways in response text
     */
    function find_payment_gateways($response_text) {
        $gateways = [
    // Major Global & Popular Gateways
    "PayPal", "Stripe", "Braintree", "Square", "Cybersource", "lemon-squeezy",
    "Authorize.Net", "2Checkout", "Adyen", "Worldpay", "SagePay",
    "Checkout.com", "Bolt", "Eway", "PayFlow", "Payeezy",
    "Paddle", "Mollie", "Viva Wallet", "Rocketgateway", "Rocketgate",
    "Rocket", "Auth.net", "Authnet", "rocketgate.com", "Recurly",

    // E-commerce Platforms
    "Shopify", "WooCommerce", "BigCommerce", "Magento", "Magento Payments",
    "OpenCart", "PrestaShop", "3DCart", "Ecwid", "Shift4Shop",
    "Shopware", "VirtueMart", "CS-Cart", "X-Cart", "LemonStand",

    // Additional Payment Solutions
    "AVS", "Convergepay", "PaySimple", "oceanpayments", "eProcessing",
    "hipay", "cybersourse", "payjunction", "usaepay", "creo",
    "SquareUp", "ebizcharge", "cpay", "Moneris", "cardknox",
    "matt sorra", "Chargify", "Paytrace", "hostedpayments", "securepay",
    "blackbaud", "LawPay", "clover", "cardconnect", "bluepay",
    "fluidpay", "Ebiz", "chasepaymentech", "Auruspay", "sagepayments",
    "paycomet", "geomerchant", "realexpayments", "Razorpay",

    // Digital Wallets & Payment Apps
    "Apple Pay", "Google Pay", "Samsung Pay", "Venmo", "Cash App",
    "Revolut", "Zelle", "Alipay", "WeChat Pay", "PayPay", "Line Pay",
    "Skrill", "Neteller", "WebMoney", "Payoneer", "Paysafe",
    "Payeer", "GrabPay", "PayMaya", "MoMo", "TrueMoney",
    "Touch n Go", "GoPay", "Dana", "JKOPay", "EasyPaisa",

    // Regional & Country Specific
    "Paytm", "UPI", "PayU", "CCAvenue",
    "Mercado Pago", "PagSeguro", "Yandex.Checkout", "PayFort", "MyFatoorah",
    "Kushki", "DLocal", "RuPay", "BharatPe", "Midtrans", "MOLPay",
    "iPay88", "KakaoPay", "Toss Payments", "NaverPay", "OVO", "GCash",
    "Bizum", "Culqi", "Pagar.me", "Rapyd", "PayKun", "Instamojo",
    "PhonePe", "BharatQR", "Freecharge", "Mobikwik", "Atom", "BillDesk",
    "Citrus Pay", "RazorpayX", "Cashfree", "PayUbiz", "EBS",

    // Buy Now Pay Later
    "Klarna", "Affirm", "Afterpay", "Zip", "Sezzle",
    "Splitit", "Perpay", "Quadpay", "Laybuy", "Openpay",
    "Atome", "Cashalo", "Hoolah", "Pine Labs", "ChargeAfter",

    // Cryptocurrency
    "BitPay", "Coinbase Commerce", "CoinGate", "CoinPayments", "Crypto.com Pay",
    "BTCPay Server", "NOWPayments", "OpenNode", "Utrust", "MoonPay",
    "Binance Pay", "CoinsPaid", "BitGo", "Flexa", "Circle",

    // European Payment Methods
    "iDEAL", "Giropay", "Sofort", "Bancontact", "Przelewy24",
    "EPS", "Multibanco", "Trustly", "PPRO", "EcoPayz",

    // Enterprise Solutions
    "ACI Worldwide", "Bank of America Merchant Services",
    "JP Morgan Payment Services", "Wells Fargo Payment Solutions",
    "Deutsche Bank Payments", "Barclaycard", "American Express Payment Gateway",
    "Discover Network", "UnionPay", "JCB Payment Gateway",

    // New Payment Technologies
    "Plaid", "Stripe Terminal", "Square Terminal", "Adyen Terminal",
    "Toast POS", "Lightspeed Payments", "Poynt", "PAX",
    "SumUp", "iZettle", "Tyro", "Vend", "ShopKeep", "Revel",

    // Additional Payment Solutions
    "HiPay", "Dotpay", "PayBox", "PayStack", "Flutterwave",
    "Opayo", "MultiSafepay", "PayXpert", "Bambora", "RedSys",
    "NPCI", "JazzCash", "Blik", "PagBank", "VibePay", "Mode",
    "Primer", "TrueLayer", "GoCardless", "Modulr", "Currencycloud",
    "Volt", "Form3", "Banking Circle", "Mangopay", "Checkout Finland",
    "Vipps", "Swish", "MobilePay"
];

        $detected = [];
        foreach ($gateways as $gateway) {
            if (stripos($response_text, $gateway) !== false) {
                $detected[] = $gateway;
            }
        }

        if (empty($detected)) {
            $detected[] = "Unknown";
        }

        return $detected;
    }

    /**
     * Find payment gateway from URL
     */
    function find_payment_gateway($url) {
        $detected_gateways = [];
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10); // Timeout after 10 seconds
        $response = curl_exec($ch);
        if ($response === false) {
            curl_close($ch);
            return ["Error"];
        }
        curl_close($ch);
        return find_payment_gateways($response);
    }

    /**
     * Check if user is admin
     */
    function is_user_admin($user_id, $admin_ids) {
        return in_array($user_id, $admin_ids);
    }

    /**
     * Find CAPTCHA details in response text
     */
    function find_captcha_details($response_text) {
        $captcha_details = [];

        // Google reCAPTCHA
        if (stripos($response_text, 'recaptcha') !== false) {
            if (stripos($response_text, 'recaptcha v1') !== false) {
                $captcha_details[] = "reCAPTCHA v1: Deprecated (legacy text-based challenges)";
            }
            if (stripos($response_text, 'recaptcha v2') !== false) {
                $captcha_details[] = "reCAPTCHA v2: 'I'm not a robot' checkbox, image/audio challenges";
            }
            if (stripos($response_text, 'recaptcha v3') !== false) {
                $captcha_details[] = "reCAPTCHA v3: Invisible scoring system (0.1–1.0 risk score)";
            }
            if (stripos($response_text, 'recaptcha enterprise') !== false) {
                $captcha_details[] = "reCAPTCHA Enterprise: Advanced risk analysis for large-scale use";
            }
        }

        // hCaptcha
        if (stripos($response_text, 'hcaptcha') !== false) {
            $captcha_details[] = "hCaptcha: Focuses on privacy; replaces reCAPTCHA in many platforms (used by Cloudflare). Image labeling challenges with adjustable difficulty";
        }

        // FunCAPTCHA
        if (stripos($response_text, 'funcaptcha') !== false) {
            $captcha_details[] = "FunCAPTCHA: Gamified challenges (e.g., 'Rotate the object')";
        }

        // Arkose Labs
        if (stripos($response_text, 'arkoselabs') !== false) {
            $captcha_details[] = "Arkose Labs (e.g., MatchKey): Dynamic 3D puzzles, adversarial AI defense";
        }

        // Text-based CAPTCHA
        if (stripos($response_text, 'text-based captcha') !== false) {
            $captcha_details[] = "Text-based CAPTCHA: Legacy distorted text/numbers (easily bypassed by bots today)";
        }

        if (empty($captcha_details)) {
            $captcha_details[] = "No CAPTCHA services detected";
        }

        return $captcha_details;
    }

    /**
     * Find Cloudflare security services in response text
     */
    function find_cloudflare_services($response_text) {
        $cloudflare_services = [];

        // Cloudflare Turnstile
        if (stripos($response_text, 'cloudflare turnstile') !== false) {
            $cloudflare_services[] = "Cloudflare Turnstile: CAPTCHA alternative with invisible/no-interaction challenges. Uses telemetry (e.g., browser fingerprints) to verify humans";
        }

        // DDoS Protection
        if (stripos($response_text, 'ddos protection') !== false) {
            $cloudflare_services[] = "DDoS Protection: Mitigates volumetric, protocol, and application-layer attacks";
        }

        // Web Application Firewall (WAF)
        if (stripos($response_text, 'web application firewall') !== false) {
            $cloudflare_services[] = "Web Application Firewall (WAF): Blocks SQLi, XSS, and OWASP Top 10 threats via customizable rules";
        }

        // Rate Limiting
        if (stripos($response_text, 'rate limiting') !== false) {
            $cloudflare_services[] = "Rate Limiting: Throttles excessive requests (e.g., brute-force attacks)";
        }

        // Bot Management
        if (stripos($response_text, 'bot management') !== false) {
            $cloudflare_services[] = "Bot Management: Detects bots using behavioral analysis, JA3 fingerprints, and machine learning";
        }

        // SSL/TLS Encryption
        if (stripos($response_text, 'ssl/tls encryption') !== false) {
            $cloudflare_services[] = "SSL/TLS Encryption: Secure data in transit with free and managed certificates";
        }

        // Zero Trust Security
        if (stripos($response_text, 'zero trust security') !== false) {
            $cloudflare_services[] = "Zero Trust Security: Secure access to apps via multi-factor authentication (MFA) and device policies";
        }

        if (empty($cloudflare_services)) {
            $cloudflare_services[] = "No Cloudflare services detected";
        }

        return $cloudflare_services;
    }

    /**
     * Find checkout details in response text
     */
    function find_checkout_details($response_text) {
        $checkout_details = [];

        // Checkout pages
        if (stripos($response_text, 'checkout') !== false) {
            $checkout_details[] = "Checkout Page Detected";
        }

        // Cart pages
        if (stripos($response_text, 'cart') !== false) {
            $checkout_details[] = "Cart Page Detected";
        }

        // Payment pages
        if (stripos($response_text, 'payment') !== false) {
            $checkout_details[] = "Payment Page Detected";
        }

        // Billing pages
        if (stripos($response_text, 'billing') !== false) {
            $checkout_details[] = "Billing Page Detected";
        }

        // Shipping pages
        if (stripos($response_text, 'shipping') !== false) {
            $checkout_details[] = "Shipping Page Detected";
        }

        if (empty($checkout_details)) {
            $checkout_details[] = "No checkout details detected";
        }

        return $checkout_details;
    }

    // Load generated codes
    $generated_codes = read_generated_codes();

    // Get the incoming update
    $update = json_decode(file_get_contents('php://input'), true);

    // Handle callback queries
    if (isset($update['callback_query'])) {
        $callback = $update['callback_query'];
        $data = $callback['data'];
        $chat_id = $callback['message']['chat']['id'];
        $message_id = $callback['message']['message_id'];
        $user_id = $callback['from']['id'];
        $first_name = $callback['from']['first_name'];

        if ($data === 'cmd') {
            // Show commands
            $new_text = <<<EOT
🎯 𝓐𝓿𝓪𝓲𝓵𝓪𝓫𝓵𝓮 𝓒𝓸𝓶𝓶𝓪𝓷𝓭𝓼

📌 𝙎𝙮𝙨𝙩𝙚𝘼𝙘𝙩𝙞𝙤𝙣𝙨:
• /register - 𝘚𝘵𝘢𝘳𝘵 𝘺𝘰𝘶𝘳 𝘫𝘰𝘶𝘳𝘯𝘦𝘺
• /info - 𝘝𝘪𝘦𝘸 𝘺𝘰𝘶𝘳 𝘱𝘳𝘰𝘧𝘪𝘭𝘦
• /gate - 𝘊𝘩𝘦𝘤𝘬 𝘢 𝘨𝘢𝘵𝘦𝘸𝘢𝘺

✨ ========================== ✨
EOT;
            $reply_markup = [
                'inline_keyboard' => [
                    [['text' => '𝗕𝗔𝗖𝗞', 'callback_data' => 'back']]
                ]
            ];
            editMessage($chat_id, $message_id, $new_text, $reply_markup, 'Markdown');
        } elseif ($data === 'back') {
            // Go back to main menu
            $url = 'https://t.me/privatecoree';
            $buttons = [
                [
                    ['text' => 'Cmds', 'callback_data' => 'cmd'],
                    ['text' => 'Channel', 'url' => $url]
                ]
            ];
            $textd = <<<EOT
•════╗
║ 👑 𝓦𝓮𝓵𝓬𝓸𝓶𝓮
║
║ 🌟 ℍ𝕖𝕪 {$first_name}
║ 🤖 𝕐𝕠𝕦𝕣 𝔾𝕒𝕥𝕖𝕨𝕒𝕪 𝔸𝕤𝕤𝕚𝕤𝕥𝕒𝕟𝕥
║ ⚡️ Type /register to Begin
╚═══════════════
EOT;
            $reply_markup = [
                'inline_keyboard' => $buttons
            ];
            editMessage($chat_id, $message_id, $textd, $reply_markup, 'Markdown');
        }
        exit;
    }
    // Enhanced CMS/Platform Detection Patterns
    $cms_patterns = [
    'Shopify' => '/cdn\.shopify\.com|shopify\.js/',
    'BigCommerce' => '/cdn\.bigcommerce\.com|bigcommerce\.com/',
    'Wix' => '/static\.parastorage\.com|wix\.com/',
    'Squarespace' => '/static1\.squarespace\.com|squarespace-cdn\.com/',
    'WooCommerce' => '/wp-content/plugins/woocommerce/',
    'Magento' => '/static/version\d+/frontend/|magento/',
    'PrestaShop' => '/prestashop\.js|prestashop/',
    'OpenCart' => '/catalog/view/theme|opencart/',
    'Shopify Plus' => '/shopify-plus|cdn\.shopifycdn\.net/',
    'Salesforce Commerce Cloud' => '/demandware\.edgesuite\.net/',
    'WordPress' => '/wp-content|wp-includes/',
    'Joomla' => '/media/jui|joomla\.js/',
    'Drupal' => '/sites/all/modules|drupal\.js/',
    'Joomla' => '/media/system/js|joomla\.javascript/',
    'Drupal' => '/sites/default/files|drupal\.settings\.js/',
    'TYPO3' => '/typo3temp|typo3/',
    'Concrete5' => '/concrete/js|concrete5/',
    'Umbraco' => '/umbraco/|umbraco\.config/',
    'Sitecore' => '/sitecore/content|sitecore\.js/',
    'Kentico' => '/cms/getresource\.ashx|kentico\.js/',
    'Episerver' => '/episerver/|episerver\.js/',
    'Custom CMS' => '/(?:<meta name="generator" content="([^"]+)")/'
];


    // Payment Card Patterns
$card_patterns = [
    'Visa' => '/visa[^a-z]|cc-visa|vi-?card/',
    'Mastercard' => '/master[ -]?card|mc-?card/',
    'Amex' => '/amex|american.?express/',
    'Discover' => '/discover/',
    'JCB' => '/jcb/',
    'Maestro' => '/maestro/',
    'UnionPay' => '/union.?pay/',
    'Diners Club' => '/diners.?club/',
    'CVV' => '/cvv|cvc|card.?verification.?value/',
    'Card Number' => '/card.?number|cc.?number|credit.?card.?number/',
    'Expiry Date' => '/expiry.?date|exp.?date|card.?expiration/',
    'Cardholder Name' => '/cardholder.?name|name.?on.?card/',
    '3D Secure' => '/3d.?secure|3.?d.?secure|verified.?by.?visa|mastercard.?securecode|secure.?code|3ds|three.?d.?secure/',
    'Credit Card Number' => '/credit.?card.?number|ccn/',
    'Card Code' => '/card.?code|security.?code/',
    'Card Verification Code' => '/card.?verification.?code|cvc2/',
    'Card Identification Number' => '/card.?identification.?number|cid/',
    'Card Issue Number' => '/card.?issue.?number|issue.?number/',
    'Card Start Date' => '/card.?start.?date|start.?date/',
    'Card Type' => '/card.?type|credit|debit/',
    'Card Brand' => '/card.?brand|visa|mastercard|amex|discover|jcb|maestro|unionpay|diners/',
    'Card Token' => '/card.?token|payment.?token/',
    'Card Bin' => '/card.?bin|bin.?number/',
    'Card Last Four Digits' => '/last.?four.?digits|last4/',
    'Card Expiry Month' => '/expiry.?month|exp.?month/',
    'Card Expiry Year' => '/expiry.?year|exp.?year/',
];




    // Enhanced Security Detection Patterns
    $security_patterns = [
        'GraphQL' => '/graphql|__schema|query\s*{/',
        'GraphQL Endpoint' => '/\/graphql|\/api\/graphql/'
    ];

    // Enhanced SSL Check Function
    function check_ssl_details($domain) {
        $context = stream_context_create([
            "ssl" => [
                "capture_peer_cert" => true,
                "verify_peer" => false,
                "verify_peer_name" => false
            ]
        ]);
        
        $client = @stream_socket_client(
            "ssl://$domain:443",
            $errno, $errstr, 30,
            STREAM_CLIENT_CONNECT,
            $context
        );
        
        if (!$client) return false;
        
        $cert = stream_context_get_params($client);
        $cert_info = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);
        
        return [
            'issuer' => $cert_info['issuer'],
            'subject' => $cert_info['subject'],
            'valid_from' => date('Y-m-d', $cert_info['validFrom_time_t']),
            'valid_to' => date('Y-m-d', $cert_info['validTo_time_t'])
        ];
    }

    // Enhanced CMS Detection
    function detect_cms_platform($content) {
        global $cms_patterns;
        $detected = [];
        
        foreach ($cms_patterns as $cms => $pattern) {
            if (preg_match($pattern, $content)) {
                $detected[] = $cms;
            }
        }
        
        // Check for meta generator tag
        if (preg_match($cms_patterns['Custom CMS'], $content, $matches)) {
            $detected[] = $matches[1];
        }
        
        return array_unique($detected);
    }

    // Enhanced Payment Card Detection
    function detect_payment_cards($content) {
        global $card_patterns;
        $detected = [];
        
        foreach ($card_patterns as $card => $pattern) {
            if (preg_match($pattern, $content, $matches)) {
                $detected[] = $card;
            }
        }
        
        return array_unique($detected);
    }

    // Enhanced Security Checks
    function enhanced_security_checks($content) {
        global $security_patterns;
        $results = [];
        
        // GraphQL Detection
        $results['GraphQL'] = false;
        foreach ($security_patterns as $key => $pattern) {
            if (preg_match($pattern, $content)) {
                $results['GraphQL'] = true;
                break;
            }
        }
        
        return $results;
    }

    // Process incoming messages
    if (isset($update['message'])) {
        $message = $update['message'];
        $chat_id = $message['chat']['id'];
        $text = isset($message['text']) ? trim($message['text']) : '';
        $message_id = $message['message_id'];
        $user = $message['from'];
        $user_id = $user['id'];
        $first_name = isset($user['first_name']) ? $user['first_name'] : 'User';
        $username = isset($user['username']) ? $user['username'] : '';

        // Load generated codes again to ensure latest data
        $generated_codes = read_generated_codes();

        // Handle commands
        if (strpos($text, '/start') === 0) {
            // Handle /start command with sequential emojis
            // 1. Send first emoji and capture message_id
            $texta = "🪄";
            $response1 = sendMessage($chat_id, $texta, null);
            $response_data1 = json_decode($response1, true);
            if (isset($response_data1['result']['message_id'])) {
                $sent_message_id = $response_data1['result']['message_id'];

                // 2. Wait for 1.5 seconds
                usleep(1500000); // 1.5 seconds

                // 3. Edit message to second emoji
                $textb = "✨";
                editMessage($chat_id, $sent_message_id, $textb, null, 'Markdown');

                // 4. Wait for another 1.5 seconds
                usleep(1500000); // 1.5 seconds

                // 5. Edit message to third emoji
                $textc = "🚀";
                editMessage($chat_id, $sent_message_id, $textc, null, 'Markdown');

                // 6. Wait for another 1.5 seconds
                usleep(1500000); // 1.5 seconds

                // 7. Send the main welcome message
                $url = 'https://t.me/privatecoree';
                $buttons = [
                    [
                        ['text' => 'Cmds', 'callback_data' => 'cmd'],
                        ['text' => 'Channel', 'url' => $url]
                    ]
                ];
                $textd = <<<EOT
┏━━━『 𝓦𝓮𝓵𝓬𝓸𝓶𝓮 』━━━┓

👋 𝕎𝕖𝕝𝕔𝕠𝕞𝕖, {$first_name}!
✨ 𝕋𝕠 『NAIROBIANGOON𝕝』

⚜️ 𝙏𝙮𝙥𝙚 /register 𝙩𝙤 𝙨𝙩𝙖𝙧𝙩

┗━━━━━━━━━━━━━━┛
EOT;
                $reply_markup = [
                    'inline_keyboard' => $buttons
                ];
                sendMessage($chat_id, $textd, null, $reply_markup, 'Markdown');
            } else {
                // Fallback if message_id is not captured
                $texta = "🪄";
                sendMessage($chat_id, $texta, null);
                usleep(1500000); // 1.5 seconds
                $textb = "✨";
                sendMessage($chat_id, $textb, null);
                usleep(1500000); // 1.5 seconds
                $textc = "🚀";
                sendMessage($chat_id, $textc, null);
                usleep(1500000); // 1.5 seconds
                $url = https://t.me/privatecoree';
                $buttons = [
                    [
                        ['text' => 'Cmds', 'callback_data' => 'cmd'],
                        ['text' => 'Channel', 'url' => $url]
                    ]
                ];
                $textd = <<<EOT
🌟 ============================ 🌟
    𝓦𝓮𝓵𝓬𝓸𝓶𝓮 𝓽𝓸 𝓖𝓪𝓽𝓮𝔀𝓪𝔂 𝓛𝓸𝓸𝓴𝓾𝓹
🌟 ============================ 🌟

👋 𝙃𝙚𝙮 {$first_name}!
🤖 𝙄'𝙢 𝙮𝙤𝙪𝙧 𝙥𝙚𝙧𝙨𝙤𝙣𝙖𝙡 𝙂𝙖𝙩𝙚𝙬𝙖𝙮 𝔸𝙨𝙨𝙞𝙨𝙩𝙖𝙣𝙩

⚠️ 𝗣𝗹𝗲𝗮𝘀𝗲 /register 𝗯𝗲𝗳𝗼𝗿𝗲 𝘂𝘀𝗶𝗻𝗴 𝗺𝗲

✨ ========================== ✨
EOT;
                $reply_markup = [
                    'inline_keyboard' => $buttons
                ];
                sendMessage($chat_id, $textd, null, $reply_markup, 'Markdown');
            }
        } elseif (strpos($text, '/register') === 0) {
            // Handle /register command
            // Append chat_id to registered_chats.txt if not already present
            $registered_chats = file_exists(REGISTERED_CHATS_FILE) ? file(REGISTERED_CHATS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
            if (!in_array($chat_id, $registered_chats)) {
                file_put_contents(REGISTERED_CHATS_FILE, $chat_id . "\n", FILE_APPEND | LOCK_EX);
                $response = "𝗧𝗵𝗮𝗻𝗸 𝘆𝗼𝘂 𝗙𝗼𝗿 𝘆𝗼𝘂𝗿 𝗥𝗲𝗴𝗶𝘀𝘁𝗿𝗮𝘁𝗶𝗼𝗻 ✅\n **Hope you will have Great Experience ahead!**";
                sendMessage($chat_id, $response, null);
            } else {
                $response = "𝗬𝗼𝘂 𝗮𝗿𝗲 𝗮𝗹𝗿𝗲𝗮𝗱𝘆 𝗿𝗲𝗴𝗶𝘀𝘁𝗲𝗿𝗲𝗱! ❤️";
                sendMessage($chat_id, $response, null);
            }
        } elseif (strpos($text, '/info') === 0) {
            // Handle /info command
            $user_mention = $username ? "@{$username}" : $first_name;

            $info_text = <<<EOT
┏━━━『 𝓟𝓻𝓸𝓯𝓲𝓵𝓮 𝓘𝓷𝓯𝓸 』━━━┓

👤 𝗨𝘀𝗲𝗿: {$user_mention}
💫 𝗣𝗹𝗮𝗻: Free

𝗜𝗗: {$user_id}

┗━━━━━━━━━━━━━━━━━┛
EOT;
            sendMessage($chat_id, $info_text, null, null, 'Markdown');
        } elseif (strpos($text, '/codes') === 0) {
            // Handle /codes command
            if (in_array($user_id, $vip)) {
                if (empty($generated_codes)) {
                    $response = 'No codes generated yet.';
                } else {
                    $response = '🔹𝗧𝗵𝗲𝘀𝗲 𝗮𝗿𝗲 𝘁𝗵𝗲 𝗖𝗼𝗱𝗲𝘀 𝘄𝗵𝗶𝗰𝗵 𝘄𝗲𝗿𝗲 𝗴𝗲𝗻𝗲𝗿𝗮𝘁𝗲𝗱 𝗮𝗻𝗱 𝗻𝗼𝘁 𝘂𝘀𝗲𝗱 𝘆𝗲𝘁. \n\n' . implode("\n", $generated_codes);
                }
                sendMessage($chat_id, $response, null);
            } else {
                $response = "⚠️ You do not have permission to use this command.";
                sendMessage($chat_id, $response, null);
            }
        } elseif (strpos($text, '/create') === 0) {
            // Handle /create command
            if (in_array($user_id, $vip)) {
                $parts = explode(' ', $text);
                if (count($parts) == 2 && is_numeric($parts[1])) {
                    $num_codes = intval($parts[1]);
                    $codes = [];
                    for ($i = 0; $i < $num_codes; $i++) {
                        $code = generate_redeem_code();
                        $codes[] = $code;
                        add_generated_code($code);
                    }
                    $code_message = " ┏━━━━━━━⍟\n┃ 𝗛𝗲𝗿𝗲 𝗶𝘀 𝘆𝗼𝘂𝗿 𝗥𝗲𝗱𝗲𝗲𝗺 𝗰𝗼𝗱𝗲𝘀 ✅\n┗━━━━━━━━━━━⊛\n\n⊙ " . implode("\n⊙ ", $codes) . " \n\n━━━━━━━━━━━━━━━━\nPlease note that each code can be redeemed once. You can redeem them using the command \n`/redeem` (@GatewayLookuppbot)";
                    sendMessage($chat_id, $code_message, null, null, 'Markdown');
                } else {
                    $response = "Usage: /create <number_of_codes>";
                    sendMessage($chat_id, $response, null);
                }
            } else {
                $response = "⚠️ You do not have permission to use this command.";
                sendMessage($chat_id, $response, null);
            }
        } elseif (strpos($text, '/redeem') === 0) {
            // Handle /redeem command
            $parts = explode(' ', $text);
            if (count($parts) >= 2) {
                $redeem_code = trim($parts[1]);
                if (in_array($redeem_code, $generated_codes)) {
                    remove_generated_code($redeem_code);

                    // Notify admin/channel
                    $notify_message = <<<EOT
                    ┏━━━『 ℝ𝕖𝕕𝕖𝕖𝕞 𝔸𝕝𝕖𝕣𝕥 』━━━┓

                    ✅ 𝙎𝙪𝙘𝙘𝙚𝙨𝙨𝙛𝙪𝙡 𝙍𝙚𝙙𝙚𝙢𝙥𝙩𝙞𝙤𝙣!

                    📌 𝗨𝘀𝗲𝗿 𝗗𝗲𝘁𝗮𝗶𝗹𝘀:
                    ├─🔹 𝗨𝘀𝗲𝗿: @{$username}
                    ├─🔹 𝗜𝗗: `{$user_id}`
                    ├─🔹 𝗖𝗼𝗱𝗲: `{$redeem_code}`
                    └─🔹 𝗕𝗼𝘁: @GatewayLookuppbot

                    ┗━━━━━━━━━━━━━━━━━┛
                    EOT;
                    sendMessage(-1002429212019, $notify_message, null, null, 'Markdown');

                    // Respond to user
                    $user_response = "𝗥𝗲𝗱𝗲𝗲𝗺𝗲𝗱 𝗦𝘂𝗰𝗰𝗲𝘀𝘀𝗳𝘂𝗹𝗹𝘆 ✅\n\n__𝗗𝗲𝘁𝗮𝗶𝗹𝘀__ :  \n**⊛ Code Redeemed** : `{$redeem_code}` \n**[⊙] User ID** : `{$user_id}`\n\n❛ ━━━━･━━━━･━━━━ ❜";
                    sendMessage($chat_id, $user_response, null, null, 'Markdown');
                } else {
                    $response = '⚠️ 𝗧𝗵𝗲 𝗽𝗿𝗼𝘃𝗶𝗱𝗲𝗱 𝗿𝗲𝗱𝗲𝗲𝗺 𝗰𝗼𝗱𝗲 𝗶𝘀 𝗶𝗻𝘃𝗮𝗹𝗶𝗱 𝗼𝗿 𝗵𝗮𝘀 𝗮𝗹𝗿𝗲𝗮𝗱𝘆 𝗯𝗲𝗲𝗻 𝗿𝗲𝗱𝗲𝗲𝗺𝗲𝗱. \n𝗣𝗹𝗲𝗮𝘀𝗲 𝗽𝗿𝗼𝘃𝗶𝗱𝗲 𝗮 𝘃𝗮𝗹𝗶𝗱 𝗰𝗼𝗱𝗲...';
                    sendMessage($chat_id, $response, null);
                }
            } else {
                $response = "Usage: /redeem <code>";
                sendMessage($chat_id, $response, null);
            }
        } elseif (strpos($text, '/approve') === 0) {
            // Handle /approve command
            if (is_user_admin($user_id, $admin_ids)) {
                $parts = explode(' ', $text);
                if (count($parts) == 2 && is_numeric($parts[1])) {
                    $approve_user_id = intval($parts[1]);
                    $pre_id[] = $approve_user_id;
                    $response = "**Added** {$approve_user_id} to **Approved** list. ✅";
                    sendMessage($chat_id, $response, null, null, 'Markdown');
                } else {
                    $response = "Invalid usage. The correct format is: /approve <user_id>";
                    sendMessage($chat_id, $response, null);
                }
            } else {
                $response = "🛑 𝗬𝗼𝘂'𝗿𝗲 𝗻𝗼𝘁 𝗮𝘂𝘁𝗵𝗼𝗿𝗶𝘇𝗲𝗱 𝘁𝗼 𝘂𝘀𝗲 𝘁𝗵𝗶𝘀 𝗰𝗼𝗺𝗺𝗮𝗻𝗱.";
                sendMessage($chat_id, $response, null);
            }
        } elseif (strpos($text, '/broadcast') === 0) {
            // Handle /broadcast command
            if (is_user_admin($user_id, $admin_ids)) {
                $parts = explode(' ', $text, 2);
                if (count($parts) == 2) {
                    $broadcast_message = $parts[1];
                    $registered_chats = file_exists(REGISTERED_CHATS_FILE) ? file(REGISTERED_CHATS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
                    foreach ($registered_chats as $chat) {
                        // You can implement forwarding replied messages if needed
                        sendMessage($chat, $broadcast_message);
                    }
                    $response = "𝗠𝗲𝘀𝘀𝗮𝗴𝗲 𝗯𝗿𝗼𝗮𝗱𝗰𝗮𝘀𝘁𝗲𝗱 𝘀𝘂𝗰𝗰𝗲𝘀𝘀𝗳𝘂𝗹𝗹𝘆. ✅";
                    sendMessage($chat_id, $response, null);
                } else {
                    $response = "Usage: /broadcast <message>";
                    sendMessage($chat_id, $response, null);
                }
            } else {
                $response = "🛑 𝗬𝗼𝘂'𝗿𝗲 𝗻𝗼𝘁 𝗮𝘂𝘁𝗵𝗼𝗿𝗶𝘇𝗲𝗱 𝘁𝗼 𝘂𝘀𝗲 𝘁𝗵𝗶𝘀 𝗰𝗼𝗺𝗺𝗮𝗻𝗱.";
                sendMessage($chat_id, $response, null);
            }
        } elseif (strpos($text, '/stats') === 0) {
            // Handle /stats command
            if (is_user_admin($user_id, $admin_ids)) {
                $registered_chats = file_exists(REGISTERED_CHATS_FILE) ? file(REGISTERED_CHATS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
                $total = count($registered_chats);
                $response = "📊 𝗧𝗼𝘁𝗮𝗹 𝗿𝗲𝗴𝗶𝘀𝘁𝗲𝗿𝗲𝗱 𝘂𝘀𝗲𝗿𝘀 : `{$total}`";
                sendMessage($chat_id, $response, null, null, 'Markdown');
            } else {
                $response = "🛑 𝗬𝗼𝘂'𝗿𝗲 𝗻𝗼𝘁 𝗮𝘂𝘁𝗵𝗼𝗿𝗶𝘇𝗲𝗱 𝘁𝗼 𝘂𝘀𝗲 𝘁𝗵𝗶𝘀 𝗰𝗼𝗺𝗺𝗮𝗻𝗱.";
                sendMessage($chat_id, $response, null);
            }
        } elseif (strpos($text, '/about') === 0) {
            // Handle /about command
            $about_text = "ℹ 𝗔𝗯𝗼𝘂𝘁 : \n**This bot is Maintained and Developed by  @Nairobiangoon** 👑\n**Use it only for Educational Purposes**, We are not responsible for any illegal activities performed by you.\n     ❛ ━━━━･━━━━･━━━━ ❜";
            sendMessage($chat_id, $about_text, null, null, 'Markdown');
        } elseif (strpos($text, '/gate') === 0) {
            // Handle /gate command
            $parts = explode(' ', $text, 2);
            if (count($parts) < 2) {
                $response = "⚠ 𝗪𝗿𝗼𝗻𝗴 𝗰𝗼𝗺𝗺𝗮𝘇𝗻 𝗳𝗼𝗿𝗺𝗮𝘁!\n𝗨𝘀𝗲 `/gate instagram.com` 𝘄𝗶𝘁𝗵𝗼𝘂𝘁 `https://`";
                sendMessage($chat_id, $response, null, null, 'Markdown');
                exit;
            }

            $url_input = trim($parts[1]);

            // Normalize URL
            $normalized_url = normalize_url($url_input);
            if ($normalized_url === false) {
                $response = "⚠️ Provide a valid URL.";
                sendMessage($chat_id, $response, null, null, 'Markdown');
                exit;
            }

            $domain = parse_url($normalized_url, PHP_URL_HOST);
            if (!$domain) {
                $response = "⚠️ Provide a valid URL.";
                sendMessage($chat_id, $response, null, null, 'Markdown');
                exit;
            }

            // Start timing
            $start_time = microtime(true);

            // Fetch website content
            $ch = curl_init($normalized_url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10); // Timeout after 10 seconds
            $response_content = curl_exec($ch);
            if ($response_content === false) {
                $response = "⚠️ Failed to fetch the website. Please try again later.";
                sendMessage($chat_id, $response, null, null, 'Markdown');
                curl_close($ch);
                exit;
            }
            $end_time = microtime(true);
            curl_close($ch);

            // Calculate time taken
            $time_taken = round($end_time - $start_time, 2);

            // Check for captcha and cloudflare
            $captcha = (stripos($response_content, 'captcha') !== false ||
                        stripos($response_content, 'protected by reCAPTCHA') !== false ||
                        stripos($response_content, "I'm not a robot") !== false ||
                        stripos($response_content, 'Recaptcha') !== false ||
                        stripos($response_content, "recaptcha/api.js") !== false);
            $cloudflare = (stripos($response_content, 'Cloudflare') !== false ||
                        stripos($response_content, 'cdnjs.cloudflare.com') !== false ||
                        stripos($response_content, 'challenges.cloudflare.com') !== false);

            // Find payment gateways
            $payment_gateways = find_payment_gateways($response_content);

            // Find CAPTCHA details
            $captcha_details = find_captcha_details($response_content);

            // Find Cloudflare services
            $cloudflare_services = find_cloudflare_services($response_content);

            // Find checkout details
            $checkout_details = find_checkout_details($response_content);

            // Enhanced Security Checks
            $security_checks = enhanced_security_checks($response_content);
            
            // CMS Detection
            $cms_platforms = detect_cms_platform($response_content);
            $cms_text = !empty($cms_platforms) ? implode(', ', $cms_platforms) : 'None';
            
            // Payment Card Detection
            $payment_cards = detect_payment_cards($response_content);
            $cards_text = !empty($payment_cards) ? implode(', ', $payment_cards) : 'None';
            
            // SSL Certificate Check
            $ssl_details = check_ssl_details($domain);
            
            // Prepare SSL Information
            $ssl_issuer = $ssl_details ? $ssl_details['issuer']['O'] ?? 'Unknown' : 'Invalid SSL';
            $ssl_subject = $ssl_details ? $ssl_details['subject']['CN'] ?? 'Unknown' : 'Invalid SSL';
            $ssl_valid = $ssl_details ? '✅' : '⛔';

            // GraphQL Check
            $graphql_detected = (stripos($response_content, 'graphql') !== false || 
                               stripos($response_content, '__schema') !== false) ? '✅' : '⛔';
            
            // Prepare response message
            $security_captcha = $captcha ? '✅' : '⛔';
            $security_cloudflare = $cloudflare ? '✅' : '⛔';
            $gateway_text = implode(', ', $payment_gateways);
            $captcha_text = implode(', ', $captcha_details);
            $cloudflare_text = implode(', ', $cloudflare_services);
            $checkout_text = implode(', ', $checkout_details);

            $checked_by = "[𝐔𝐬𝐞𝐫](tg://user?id={$user_id})";

            $info_fetched = <<<EOT
┏━━━━『 𝓖𝓪𝓽𝓮𝔀𝓪𝔂 𝓡𝓮𝓼𝓾𝓵𝓽𝓼 』━━━━┓

🔍 𝗗𝗼𝗺𝗮𝗶𝗻: {$domain}
💳 𝗚𝗮𝘁𝗲𝘄𝗮𝘆𝘀: {$gateway_text}
🔒 𝗖𝗔𝗣𝗧𝗖𝗛𝗔: {$captcha_text}
🔒 𝗖𝗟𝗢𝗨𝗗𝗙𝗟𝗔𝗥𝗘: {$cloudflare_text}
🛒 𝗖𝗛𝗘𝗖𝗞𝗢𝗨𝗧: {$checkout_text}

🛡️ 𝗦𝗲𝗰𝘂𝗿𝗶𝘁𝘆:
   ├─ 𝗖𝗮𝗽𝘁𝗰𝗵𝗮: {$security_captcha}
   ├─ 𝗖𝗹𝗼𝘂𝗱𝗳𝗹𝗮𝗿𝗲: {$security_cloudflare}
   └─ 𝗚𝗿𝗮𝗽𝗵𝗤𝗟: {$graphql_detected}

🔐 𝗦𝗦𝗟 𝗗𝗲𝘁𝗮𝗶𝗹𝘀:
   ├─ 𝗜𝘀𝘀𝘂𝗲𝗿: {$ssl_issuer}
   ├─ 𝗦𝘂𝗯𝗷𝗲𝗰𝘁: {$ssl_subject}
   └─ 𝗩𝗮𝗹𝗶𝗱: {$ssl_valid}

🛍️ 𝗣𝗹𝗮𝘁𝗳𝗼𝗿𝗺:
   ├─ 𝗖𝗠𝗦: {$cms_text}
   └─ 𝗖𝗮𝗿𝗱𝘀: {$cards_text}

⏱️ 𝗧𝗶𝗺𝗲: {$time_taken}s
👤 𝗖𝗵𝗲𝗰𝗸𝗲𝗱 𝗯𝘆: {$checked_by}

┗━━━━『 @Nairobiangoon』━━━━
EOT;

            // Send response to user
            sendMessage($chat_id, $info_fetched, null, null, 'Markdown');

            // Prepare notification message for admin/channel
            $notify_message = <<<EOT
┏━━━━『 𝓖𝓪𝓽𝓮𝔀𝓪𝔂 𝓡𝓮𝓼𝓾𝓵𝓽𝓼 』━━━━┓

🔍 𝗗𝗼𝗺𝗮𝗶𝗻: {$domain}
💳 𝗚𝗮𝘁𝗲𝘄𝗮𝘆𝘀: {$gateway_text}
🔒 𝗖𝗔𝗣𝗧𝗖𝗛𝗔: {$captcha_text}
🔒 𝗖𝗟𝗢𝗨𝗗𝗙𝗟𝗔𝗥𝗘: {$cloudflare_text}
🛒 𝗖𝗛𝗘𝗖𝗞𝗢𝗨𝗧: {$checkout_text}

🛡️ 𝗦𝗲𝗰𝘂𝗿𝗶𝘁𝘆:
   ├─ 𝗖𝗮𝗽𝘁𝗰𝗵𝗮: {$security_captcha}
   ├─ 𝗖𝗹𝗼𝘂𝗱𝗳𝗹𝗮𝗿𝗲: {$security_cloudflare}
   └─ 𝗚𝗿𝗮𝗽𝗵𝗤𝗟: {$graphql_detected}

🔐 𝗦𝗦𝗟 𝗗𝗲𝘁𝗮𝗶𝗹𝘀:
   ├─ 𝗜𝘀𝘀𝘂𝗲𝗿: {$ssl_issuer}
   ├─ 𝗦𝘂𝗯𝗷𝗲𝗰𝘁: {$ssl_subject}
   └─ 𝗩𝗮𝗹𝗶𝗱: {$ssl_valid}

🛍️ 𝗣𝗹𝗮𝘁𝗳𝗼𝗿𝗺:
   ├─ 𝗖𝗠𝗦: {$cms_text}
   └─ 𝗖𝗮𝗿𝗱𝘀: {$cards_text}

⏱️ 𝗧𝗶𝗺𝗲: {$time_taken}s
👤 𝗖𝗵𝗲𝗰𝗸𝗲𝗱 𝗯𝘆: {$checked_by}

┗━━━━『 @Nairobiangoon』━━━━
EOT;

            // sendMessage(-1002429212019, $notify_message, null, null, 'Markdown');

        } elseif (strpos($text, '/mgate') === 0) {
            // Handle /mgate command
            $lines = explode("\n", $text);
            $urls = [];

            // First, extract valid URLs from input
            foreach ($lines as $line) {
                $line = trim($line);
                if (strpos($line, '/mgate') === 0) {
                    continue;
                }

                // Extract URLs and domains from line
                if (preg_match_all('/(https?:\/\/)?([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}([\/\w-]*)*\/?/', $line, $matches)) {
                    foreach ($matches[0] as $match) {
                        $url = trim($match);
                        if (!preg_match('/^https?:\/\//i', $url)) {
                            $url = 'http://' . $url;
                        }
                        $parsed = parse_url($url);
                        if (isset($parsed['host'])) {
                            // Only add if not already in array
                            if (!in_array($parsed['host'], $urls)) {
                                $urls[] = $parsed['host'];
                            }
                        }
                    }
                }
            }

            if (empty($urls)) {
                sendMessage($chat_id, "⚠️ No valid URLs found.", null, null, 'Markdown');
                return; // Use return instead of exit
            }

            // Limit number of URLs to process
            $max_urls = 10;
            if (count($urls) > $max_urls) {
                $urls = array_slice($urls, 0, $max_urls);
                sendMessage($chat_id, "⚠️ Processing first $max_urls URLs only.", null, null, 'Markdown');
            }

            // Process each unique URL
            foreach ($urls as $url) {
                // Normalize URL
                $normalized_url = "http://" . $url;

                // Start timing
                $start_time = microtime(true);

                // Fetch website content
                $ch = curl_init($normalized_url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 10);
                $response_content = curl_exec($ch);

                if ($response_content === false) {
                    sendMessage($chat_id, "⚠️ Failed to fetch: {$url}", null, null, 'Markdown');
                    curl_close($ch);
                    continue;
                }
                curl_close($ch);

                $end_time = microtime(true);
                $time_taken = round($end_time - $start_time, 2);

                // Check security features
                $captcha = (stripos($response_content, 'captcha') !== false ||
                            stripos($response_content, 'protected by reCAPTCHA') !== false ||
                            stripos($response_content, "I'm not a robot") !== false ||
                            stripos($response_content, 'Recaptcha') !== false ||
                            stripos($response_content, "recaptcha/api.js") !== false);

                $cloudflare = (stripos($response_content, 'Cloudflare') !== false ||
                            stripos($response_content, 'cdnjs.cloudflare.com') !== false ||
                            stripos($response_content, 'challenges.cloudflare.com') !== false);

                // Find payment gateways
                $payment_gateways = find_payment_gateways($response_content);
                $gateway_text = implode(', ', $payment_gateways);

                // Find CAPTCHA details
                $captcha_details = find_captcha_details($response_content);

                // Find Cloudflare services
                $cloudflare_services = find_cloudflare_services($response_content);

                // Find checkout details
                $checkout_details = find_checkout_details($response_content);

                // Enhanced Security Checks
                $security_checks = enhanced_security_checks($response_content);
                
                // CMS Detection
                $cms_platforms = detect_cms_platform($response_content);
                $cms_text = !empty($cms_platforms) ? implode(', ', $cms_platforms) : 'None';
                
                // Payment Card Detection
                $payment_cards = detect_payment_cards($response_content);
                $cards_text = !empty($payment_cards) ? implode(', ', $payment_cards) : 'None';
                
                // SSL Certificate Check
                $ssl_details = check_ssl_details($url);
                
                // Prepare SSL Information
                $ssl_issuer = $ssl_details ? $ssl_details['issuer']['O'] ?? 'Unknown' : 'Invalid SSL';
                $ssl_subject = $ssl_details ? $ssl_details['subject']['CN'] ?? 'Unknown' : 'Invalid SSL';
                $ssl_valid = $ssl_details ? '✅' : '⛔';

                // GraphQL Check
                $graphql_detected = (stripos($response_content, 'graphql') !== false || 
                                   stripos($response_content, '__schema') !== false) ? '✅' : '⛔';

                // Security indicators
                $security_captcha = $captcha ? '✅' : '⛔';
                $security_cloudflare = $cloudflare ? '✅' : '⛔';
                $captcha_text = implode(', ', $captcha_details);
                $cloudflare_text = implode(', ', $cloudflare_services);
                $checkout_text = implode(', ', $checkout_details);

                $checked_by = "[𝐔𝐬𝐞𝐫](tg://user?id={$user_id})";

                // Prepare and send individual message for each URL
                $message = <<<EOT
┏━━━━『 𝓖𝓪𝓽𝓮𝔀𝓪𝔂 𝓡𝓮𝓼𝓾𝓵𝓽𝓼 』━━━━┓

🔍 𝗗𝗼𝗺𝗮𝗶𝗻: {$url}
💳 𝗚𝗮𝘁𝗲𝘄𝗮𝘆𝘀: {$gateway_text}
🔒 𝗖𝗔𝗣𝗧𝗖𝗛𝗔: {$captcha_text}
🔒 𝗖𝗟𝗢𝗨𝗗𝗙𝗟𝗔𝗥𝗘: {$cloudflare_text}
🛒 𝗖𝗛𝗘𝗖𝗞𝗢𝗨𝗧: {$checkout_text}

🛡️ 𝗦𝗲𝗰𝘂𝗿𝗶𝘁𝘆:
   ├─ 𝗖𝗮𝗽𝘁𝗰𝗵𝗮: {$security_captcha}
   ├─ 𝗖𝗹𝗼𝘂𝗱𝗳𝗹𝗮𝗿𝗲: {$security_cloudflare}
   └─ 𝗚𝗿𝗮𝗽𝗵𝗤𝗟: {$graphql_detected}

🔐 𝗦𝗦𝗟 𝗗𝗲𝘁𝗮𝗶𝗹𝘀:
   ├─ 𝗜𝘀𝘀𝘂𝗲𝗿: {$ssl_issuer}
   ├─ 𝗦𝘂𝗯𝗷𝗲𝗰𝘁: {$ssl_subject}
   └─ 𝗩𝗮𝗹𝗶𝗱: {$ssl_valid}

🛍️ 𝗣𝗹𝗮𝘁𝗳𝗼𝗿𝗺:
   ├─ 𝗖𝗠𝗦: {$cms_text}
   └─ 𝗖𝗮𝗿𝗱𝘀: {$cards_text}

⏱️ 𝗧𝗶𝗺𝗲: {$time_taken}s
👤 𝗖𝗵𝗲𝗰𝗸𝗲𝗱 𝗯𝘆: {$checked_by}

┗━━━━『 @Nairobiangoon』━━━━
EOT;

                // Send individual message
                sendMessage($chat_id, $message, null, null, 'Markdown');

                // Add a small delay between messages to prevent flooding
                sleep(1);
            }
        } else {
            // Handle other commands or messages if needed
        }
    }
?>
