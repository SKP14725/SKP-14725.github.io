<?php
header('Content-Type: application/json');

// 配置
$usersFile = 'users.txt';
$ipBlacklistFile = 'ip_blacklist.txt';
$ipRateLimitFile = 'ip_rate_limit.txt';
$action = $_GET['action'] ?? '';
$response = ['success' => false, 'message' => ''];

// 限制配置
define('MAX_USERNAME_LENGTH', 20);
define('MAX_PASSWORD_LENGTH', 20);
define('MAX_REGISTER_ATTEMPTS', 5);
define('RATE_LIMIT_TIME', 3600); // 1小时

try {
    // 只接受POST请求
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('只支持POST请求');
    }

    // 获取客户端IP
    $clientIP = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '';

    // 检查IP是否在黑名单中
    if (file_exists($ipBlacklistFile)) {
        $blacklistedIPs = file($ipBlacklistFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (in_array($clientIP, $blacklistedIPs)) {
            throw new Exception('您的IP已被禁止访问');
        }
    }

    // 获取输入数据
    $input = json_decode(file_get_contents('php://input'), true);
    if ($input === null && json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('无效的JSON数据: ' . json_last_error_msg());
    }

    // 验证必要字段
    if (empty($input['username']) || empty($input['password'])) {
        throw new Exception('用户名和密码不能为空');
    }

    $username = trim($input['username']);
    $password = $input['password'];

    // 验证用户名和密码长度
    if (strlen($username) > MAX_USERNAME_LENGTH) {
        throw new Exception('用户名长度不能超过'.MAX_USERNAME_LENGTH.'个字符');
    }
    
    if (strlen($password) > MAX_PASSWORD_LENGTH) {
        throw new Exception('密码长度不能超过'.MAX_PASSWORD_LENGTH.'个字符');
    }

    // 根据action执行不同操作
    switch ($action) {
        case 'register':
            // 检查注册频率限制
            checkRateLimit($clientIP);
            
            // 注册逻辑
            $users = [];
            if (file_exists($usersFile)) {
                $users = file($usersFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                foreach ($users as $userLine) {
                    $user = json_decode($userLine, true);
                    if ($user && isset($user['username']) && $user['username'] === $username) {
                        throw new Exception('用户名已存在');
                    }
                }
            }

            // 创建新用户
            $userData = [
                'id' => uniqid(),
                'username' => $username,
                'password' => password_hash($password, PASSWORD_DEFAULT),
                'created_at' => date('Y-m-d H:i:s'),
                'ip' => $clientIP
            ];

            // 确保目录可写
            if (!is_writable(dirname($usersFile))) {
                throw new Exception('用户数据存储不可写');
            }

            file_put_contents($usersFile, json_encode($userData) . PHP_EOL, FILE_APPEND);
            $response = [
                'success' => true,
                'message' => '注册成功',
                'user' => ['id' => $userData['id'], 'username' => $userData['username']]
            ];
            break;

        case 'login':
            // 登录逻辑
            if (!file_exists($usersFile)) {
                throw new Exception('用户数据文件不存在');
            }

            $users = file($usersFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            $found = false;

            foreach ($users as $userLine) {
                $user = json_decode($userLine, true);
                if ($user && isset($user['username']) && $user['username'] === $username) {
                    if (password_verify($password, $user['password'])) {
                        $response = [
                            'success' => true,
                            'message' => '登录成功',
                            'user' => ['id' => $user['id'], 'username' => $user['username']]
                        ];
                        $found = true;
                        break;
                    }
                }
            }

            if (!$found) {
                throw new Exception('用户名或密码错误');
            }
            break;

        default:
            throw new Exception('无效的操作类型');
    }

} catch (Exception $e) {
    $response['message'] = $e->getMessage();
    http_response_code(400); // 设置错误状态码
}

echo json_encode($response, JSON_UNESCAPED_UNICODE);

/**
 * 检查IP注册频率限制
 */
function checkRateLimit($ip) {
    global $ipRateLimitFile, $ipBlacklistFile;
    
    if (!file_exists($ipRateLimitFile)) {
        if (!file_put_contents($ipRateLimitFile, json_encode([]))) {
            throw new Exception('无法创建频率限制文件');
        }
    }
    
    $rateData = json_decode(file_get_contents($ipRateLimitFile), true);
    if ($rateData === null) {
        $rateData = [];
    }
    
    $now = time();
    
    // 清理过期的记录
    foreach ($rateData as $recordedIP => $data) {
        if ($now - $data['last_attempt'] > RATE_LIMIT_TIME) {
            unset($rateData[$recordedIP]);
        }
    }
    
    // 检查当前IP
    if (isset($rateData[$ip])) {
        if ($rateData[$ip]['attempts'] >= MAX_REGISTER_ATTEMPTS) {
            // 添加到黑名单
            file_put_contents($ipBlacklistFile, $ip . PHP_EOL, FILE_APPEND);
            throw new Exception('注册尝试过于频繁，您的IP已被禁止');
        }
        $rateData[$ip]['attempts']++;
        $rateData[$ip]['last_attempt'] = $now;
    } else {
        $rateData[$ip] = [
            'attempts' => 1,
            'last_attempt' => $now
        ];
    }
    
    if (!file_put_contents($ipRateLimitFile, json_encode($rateData))) {
        throw new Exception('无法更新频率限制数据');
    }
}
?>