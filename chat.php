<?php
header('Content-Type: application/json');

// 配置文件
$usersFile = 'users.txt';
$messagesFile = 'messages.txt';
$ipBlacklistFile = 'ip_blacklist.txt';
$ipRateLimitFile = 'ip_rate_limit.txt';
$response = ['success' => false, 'message' => ''];

// 支持的聊天操作
$actions = ['send', 'get', 'clear'];
$action = $_GET['action'] ?? '';

// 限制配置
define('MAX_MESSAGE_LENGTH', 60);
define('MAX_MESSAGES_PER_MINUTE', 10); // 每分钟最多发送10条消息
define('RATE_LIMIT_WINDOW', 60); // 60秒的时间窗口
define('BLACKLIST_THRESHOLD', 30); // 30次违规后拉黑IP

try {
    // 验证请求方法
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
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('无效的JSON数据');
    }

    // 验证必须字段
    if (empty($input['username']) || empty($input['password'])) {
        throw new Exception('需要用户名和密码进行验证');
    }

    $username = trim($input['username']);
    $password = $input['password'];

    // 验证用户身份
    if (!file_exists($usersFile)) {
        throw new Exception('用户数据文件不存在');
    }

    $users = file($usersFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $userValid = false;

    foreach ($users as $userLine) {
        $user = json_decode($userLine, true);
        if ($user && isset($user['username']) && $user['username'] === $username) {
            if (password_verify($password, $user['password'])) {
                $userValid = true;
                break;
            }
        }
    }

    if (!$userValid) {
        throw new Exception('用户名或密码错误');
    }

    // 根据action处理不同操作
    if (!in_array($action, $actions)) {
        throw new Exception('无效的操作类型');
    }

    switch ($action) {
        case 'send':
            // 检查消息发送频率
            checkMessageRateLimit($clientIP);
            
            // 发送消息
            if (empty($input['message'])) {
                throw new Exception('消息内容不能为空');
            }

            $messageText = trim($input['message']);
            if (strlen($messageText) > MAX_MESSAGE_LENGTH) {
                throw new Exception('消息长度不能超过'.MAX_MESSAGE_LENGTH.'个字符');
            }

            $message = [
                'username' => $username,
                'message' => $messageText,
                'timestamp' => date('Y-m-d H:i:s'),
                'ip' => $clientIP
            ];

            file_put_contents($messagesFile, json_encode($message) . PHP_EOL, FILE_APPEND);
            $response = [
                'success' => true,
                'message' => '消息发送成功',
                'data' => $message
            ];
            break;

        case 'get':
            // 获取消息
            $messages = [];
            if (file_exists($messagesFile)) {
                $messageLines = file($messagesFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                foreach ($messageLines as $line) {
                    $messages[] = json_decode($line, true);
                }
            }

            $response = [
                'success' => true,
                'message' => '获取消息成功',
                'data' => $messages
            ];
            break;

        case 'clear':
            // 清空消息（生产环境应添加管理员权限检查）
            if (file_exists($messagesFile)) {
                unlink($messagesFile);
            }
            $response = [
                'success' => true,
                'message' => '聊天记录已清空'
            ];
            break;
    }

} catch (Exception $e) {
    $response['message'] = $e->getMessage();
}

echo json_encode($response);

/**
 * 检查消息发送频率限制
 */
function checkMessageRateLimit($ip) {
    global $ipRateLimitFile, $ipBlacklistFile;
    
    if (!file_exists($ipRateLimitFile)) {
        file_put_contents($ipRateLimitFile, json_encode([]));
    }
    
    $rateData = json_decode(file_get_contents($ipRateLimitFile), true) ?: [];
    $now = time();
    
    // 初始化IP数据
    if (!isset($rateData[$ip])) {
        $rateData[$ip] = [
            'count' => 0,
            'last_reset' => $now,
            'violations' => 0
        ];
    }
    
    // 重置计数器如果超过时间窗口
    if ($now - $rateData[$ip]['last_reset'] > RATE_LIMIT_WINDOW) {
        $rateData[$ip]['count'] = 0;
        $rateData[$ip]['last_reset'] = $now;
    }
    
    // 检查当前计数
    $rateData[$ip]['count']++;
    
    if ($rateData[$ip]['count'] > MAX_MESSAGES_PER_MINUTE) {
        $rateData[$ip]['violations']++;
        
        // 如果违规次数超过阈值，加入黑名单
        if ($rateData[$ip]['violations'] >= BLACKLIST_THRESHOLD) {
            file_put_contents($ipBlacklistFile, $ip . PHP_EOL, FILE_APPEND);
            throw new Exception('消息发送过于频繁，您的IP已被禁止');
        }
        
        throw new Exception('消息发送过于频繁，请稍后再试');
    }
    
    // 保存更新后的频率数据
    file_put_contents($ipRateLimitFile, json_encode($rateData));
}
?>