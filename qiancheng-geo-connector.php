<?php
/**
 * Plugin Name: 前程 GEO 连接器
 * Description: 全站统计、公开内容目录自动同步与连接诊断。
 * Version: 0.3.0
 * License: GPL-3.0-or-later
 * Requires PHP: 7.4
 * Requires at least: 5.9
 */
if (!defined('ABSPATH')) exit;
function qcgeo_options() {
    return wp_parse_args(get_option('qcgeo_options', array()), array('url'=>'https://geo.szgylco.cn','id'=>'','username'=>'','secret'=>'','auto'=>0));
}
function qcgeo_state($patch=null) {
    $s=get_option('qcgeo_state',array());
    if (is_array($patch)) { $s=array_merge($s,$patch); update_option('qcgeo_state',$s,false); }
    return $s;
}
function qcgeo_crypt($text,$decrypt=false) {
    if (!function_exists('openssl_encrypt')) return new WP_Error('crypto','服务器缺少 OpenSSL，无法安全保存凭据。');
    $key=hash('sha256',wp_salt('auth').'qcgeo',true);
    if ($decrypt) {
        $raw=base64_decode($text,true);
        if ($raw===false || strlen($raw)<29) return new WP_Error('crypto','凭据不可读取，请重新填写。');
        $out=openssl_decrypt(substr($raw,28),'aes-256-gcm',$key,OPENSSL_RAW_DATA,substr($raw,0,12),substr($raw,12,16));
    } else {
        $iv=random_bytes(12);$tag='';$cipher=openssl_encrypt($text,'aes-256-gcm',$key,OPENSSL_RAW_DATA,$iv,$tag);
        $out=$cipher===false ? false : base64_encode($iv.$tag.$cipher);
    }
    return $out===false ? new WP_Error('crypto','凭据不可读取，请重新填写。') : $out;
}
function qcgeo_validate($v) {
    $old=qcgeo_options();
    if (!is_array($v)) return $old;
    $url=untrailingslashit(esc_url_raw($v['url']??'',array('https')));
    $parts=wp_parse_url($url);$id=sanitize_text_field($v['id']??'');
    if (!$url || !$parts || ($parts['scheme']??'')!=='https' || !empty($parts['user']) || !empty($parts['pass']) || !empty($parts['query']) || !empty($parts['fragment']) || !preg_match('/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i',$id)) {
        add_settings_error('qcgeo','invalid','请输入 HTTPS 平台地址和有效的网站 UUID。'); return $old;
    }
    $new=array('url'=>$url,'id'=>$id,'username'=>sanitize_text_field($v['username']??''),'secret'=>$old['secret'],'auto'=>empty($v['auto'])?0:1);
    if ($new['url']!==$old['url'] || $new['username']!==$old['username'] || !empty($v['clear_secret'])) $new['secret']='';
    if (!empty($v['password'])) {
        $encrypted=qcgeo_crypt($v['password']);
        if (is_wp_error($encrypted)) {add_settings_error('qcgeo','crypto',$encrypted->get_error_message());return $old;}
        $new['secret']=$encrypted;
    }
    if ($new['auto'] && (!$new['secret'] || !$new['username'])) {
        $new['auto']=0;add_settings_error('qcgeo','credentials','连接凭据未填写，自动同步保持关闭。');
    }
    return $new;
}
add_action('admin_init',function(){register_setting('qcgeo','qcgeo_options',array('sanitize_callback'=>'qcgeo_validate'));});
add_filter('plugin_action_links_'.plugin_basename(__FILE__),function($links){
    if(current_user_can('manage_options')) array_unshift($links,'<a href="'.esc_url(admin_url('options-general.php?page=qcgeo')).'">设置</a>');return $links;
});
add_filter('cron_schedules',function($s){$s['qcgeo_15min']=array('interval'=>900,'display'=>'前程 GEO 每15分钟');return $s;});
function qcgeo_schedule() {
    if(qcgeo_options()['auto']) {if(!wp_next_scheduled('qcgeo_periodic')) wp_schedule_event(time()+60,'qcgeo_15min','qcgeo_periodic');}
    else {wp_clear_scheduled_hook('qcgeo_periodic');wp_clear_scheduled_hook('qcgeo_changed');}
}
add_action('update_option_qcgeo_options',function($old,$new){
    delete_transient('qcgeo_token');
    qcgeo_state(array('connection'=>'待检测','connection_at'=>0,'last_success'=>0,'count'=>0,'error'=>'','blocked'=>false,'retry_at'=>0,'hash'=>'','paths'=>array(),'removed'=>0));qcgeo_schedule();
},10,2);
register_activation_hook(__FILE__,'qcgeo_schedule');
register_deactivation_hook(__FILE__,function(){wp_clear_scheduled_hook('qcgeo_periodic');wp_clear_scheduled_hook('qcgeo_changed');delete_transient('qcgeo_token');});
function qcgeo_content_changed($id) {
    if(wp_is_post_revision($id) || wp_is_post_autosave($id)) return;
    $p=get_post($id);if(!$p || !in_array($p->post_type,get_post_types(array('public'=>true)),true))return;
    if(qcgeo_options()['auto'] && !wp_next_scheduled('qcgeo_changed')) wp_schedule_single_event(time()+60,'qcgeo_changed');
}
add_action('save_post','qcgeo_content_changed');add_action('before_delete_post','qcgeo_content_changed');
function qcgeo_http($path,$method='GET',$body=null,$token='') {
    $o=qcgeo_options();
    if(!$o['id'] || strpos($o['url'],'https://')!==0) return new WP_Error('config','请先保存平台地址和网站 ID。');
    $args=array('method'=>$method,'timeout'=>20,'redirection'=>0,'limit_response_size'=>2*1024*1024,'headers'=>array('Content-Type'=>'application/json'));
    if($token) $args['headers']['Authorization']='Bearer '.$token;
    if($body!==null) $args['body']=wp_json_encode($body);
    $r=wp_safe_remote_request($o['url'].$path,$args);
    if(is_wp_error($r))return new WP_Error('network','连接失败：请检查平台域名、HTTPS 和服务器网络。');
    $code=wp_remote_retrieve_response_code($r);
    if($code<200 || $code>=300) {
        $messages=array(401=>'登录失效或账号密码不正确，请重新填写并测试连接。',403=>'账号没有此网站权限，或请求被防火墙拒绝。',404=>'未找到平台接口或网站，请检查平台地址与网站 ID。',429=>'平台限流，已暂停自动重试，请稍后手动测试连接。');
        return new WP_Error(in_array($code,array(401,403,429),true)?'auth':'http',$messages[$code]??('平台请求失败（HTTP '.$code.'）。'));
    }
    $data=json_decode(wp_remote_retrieve_body($r),true);
    return is_array($data)?$data:new WP_Error('response','平台未返回有效 JSON，请检查地址。');
}
function qcgeo_token() {
    $cached=get_transient('qcgeo_token');if($cached)return $cached;
    $o=qcgeo_options();if(!$o['username'] || !$o['secret'])return new WP_Error('config','请在连接设置中填写 GEOInflow 账号和密码，然后保存。');
    $password=qcgeo_crypt($o['secret'],true);if(is_wp_error($password))return $password;
    $r=qcgeo_http('/api/auth/login','POST',array('username'=>$o['username'],'password'=>$password));unset($password);
    if(is_wp_error($r))return $r;
    if(!empty($r['requiresTwoFactor']))return new WP_Error('auth','此账号要求二次验证，当前自动连接不支持。请使用平台允许的专用接入方式，不要关闭二次验证。');
    if(empty($r['token']) || !is_string($r['token']))return new WP_Error('auth','平台没有返回完整登录凭据。');
    set_transient('qcgeo_token',$r['token'],300);return $r['token'];
}
function qcgeo_test() {
    $token=qcgeo_token();if(is_wp_error($token))return $token;
    $r=qcgeo_http('/api/websites/'.rawurlencode(qcgeo_options()['id']),'GET',null,$token);
    if(is_wp_error($r))return $r;
    $domain=strtolower(trim($r['domain']??''));$domain=wp_parse_url(strpos($domain,'://')===false?'https://'.$domain:$domain,PHP_URL_HOST);
    if(!$domain || $domain!==strtolower(wp_parse_url(home_url(),PHP_URL_HOST))) return new WP_Error('domain','平台网站域名与当前 WordPress 不一致，请检查网站 ID，避免同步到其他网站。');
    qcgeo_state(array('connection'=>'已连接（读取权限通过）','connection_at'=>time(),'error'=>'','blocked'=>false,'retry_at'=>0));return $token;
}
function qcgeo_fail($error) {
    if($error->get_error_code()==='auth')delete_transient('qcgeo_token');
    qcgeo_state(array('connection'=>'连接或同步失败，需重新检测','error'=>$error->get_error_message(),'last_attempt'=>time(),'blocked'=>in_array($error->get_error_code(),array('auth','config','crypto','domain'),true),'retry_at'=>time()+900));return $error;
}
function qcgeo_rows() {
    $rows=array();$page=1;
    do {
        $request=new WP_REST_Request('GET');$request->set_param('page',$page);
        $d=qcgeo_catalog($request)->get_data();$rows=array_merge($rows,$d['items']);$page++;
        if(count($rows)>5000)return new WP_Error('limit','目录超过本版5000条上限，请联系维护人员配置分批队列。');
    } while($page<=$d['pages']);
    return $rows;
}
function qcgeo_sync($manual=false) {
    $state=qcgeo_state();
    if(!$manual && (!qcgeo_options()['auto'] || !empty($state['blocked']) || ($state['retry_at']??0)>time()))return;
    $lock=get_option('qcgeo_lock',0);if($lock && $lock<time()-300)delete_option('qcgeo_lock');
    if(!add_option('qcgeo_lock',time(),'','no'))return new WP_Error('busy','已有同步任务运行，请稍后刷新。');
    try {
        $token=qcgeo_test();if(is_wp_error($token))return qcgeo_fail($token);
        $rows=qcgeo_rows();if(is_wp_error($rows))return qcgeo_fail($rows);
        $paths=array_column($rows,'url');$old=$state['paths']??array();$removed=array_values(array_diff($old,$paths));
        $hash=hash('sha256',wp_json_encode($rows));
        if(!$rows) {qcgeo_state(array('removed'=>count($old)));return qcgeo_fail(new WP_Error('empty','公开目录为空；平台不支持清空目录，未执行导入。'));}
        $changed=$hash!==($state['hash']??'');
        $accepted=0;
        if($changed || $manual)foreach(array_chunk($rows,500) as $chunk) {
            $r=qcgeo_http('/api/liekan/websites/'.rawurlencode(qcgeo_options()['id']).'/catalog','PUT',array('format'=>'json','content'=>wp_json_encode($chunk)),$token);
            if(is_wp_error($r))return qcgeo_fail($r);
            if(($r['accepted']??-1)!==count($chunk))return qcgeo_fail(new WP_Error('count','平台确认条数不一致，未标记整批成功；下次将重新核对。'));
            $accepted+=$r['accepted'];
        }
        $patch=array('last_attempt'=>time(),'last_check'=>time(),'hash'=>$hash,'count'=>count($rows),'paths'=>array_values(array_unique(array_merge($old,$paths))),'removed'=>count($removed),'error'=>'','blocked'=>false,'retry_at'=>0);
        if($changed || $manual)$patch['last_success']=time();
        qcgeo_state($patch);return array('accepted'=>$accepted,'unchanged'=>!$changed && !$manual);
    } finally {delete_option('qcgeo_lock');}
}
add_action('qcgeo_periodic','qcgeo_sync');add_action('qcgeo_changed','qcgeo_sync');
add_action('admin_post_qcgeo_action',function(){
    if(!current_user_can('manage_options'))wp_die('无权操作',403);
    check_admin_referer('qcgeo_action');
    $action=sanitize_key(wp_unslash($_POST['qcgeo_action']??''));
    if($action==='test') {delete_transient('qcgeo_token');$r=qcgeo_test();if(is_wp_error($r))qcgeo_fail($r);}
    elseif($action==='sync') {$r=qcgeo_sync(true);if(is_wp_error($r) && $r->get_error_code()==='busy')qcgeo_state(array('error'=>$r->get_error_message()));}
    wp_safe_redirect(admin_url('options-general.php?page=qcgeo'));exit;
});
function qcgeo_time($t){return $t?wp_date('Y-m-d H:i:s',$t):'尚无记录';}
add_action('admin_menu',function(){add_options_page('前程 GEO 连接器','前程 GEO 连接器','manage_options','qcgeo','qcgeo_admin');});
function qcgeo_admin() {
    if(!current_user_can('manage_options'))return;
    $o=qcgeo_options();$s=qcgeo_state();$rows=qcgeo_rows();$count=is_wp_error($rows)?'超出上限':count($rows);
    ?>
    <div class="wrap qcgeo"><h1>前程 GEO 连接器 <small>0.3.0</small></h1>
    <p>启用自动同步后，新增和更新的公开内容会进入待同步队列；实际结果以平台回执为准。</p>
    <?php settings_errors('qcgeo'); ?>
    <style>.qcgeo{max-width:1060px}.qcgeo small{font-size:13px;color:#646970}.qcgeo .qc-panel{background:#fff;border:1px solid #c3c4c7;padding:20px 24px;margin:20px 0}.qcgeo .qc-status{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:20px}.qcgeo .qc-status strong{display:block;font-size:18px;margin-top:8px}.qcgeo .qc-status span{color:#50575e}.qcgeo .qc-actions{display:flex;gap:12px;flex-wrap:wrap}.qcgeo input.regular-text{max-width:100%;width:440px}.qcgeo .qc-detail{color:#50575e;line-height:1.7}.qcgeo .form-table th{width:145px}.qcgeo .notice{margin:16px 0}.qcgeo code{overflow-wrap:anywhere}@media(max-width:782px){.qcgeo .qc-status{grid-template-columns:1fr}.qcgeo .qc-panel{padding:16px}.qcgeo .form-table th{width:auto}}</style>
    <div class="qc-panel"><h2>接入状态</h2><div class="qc-status">
    <div><span>平台连接</span><strong><?php echo esc_html($s['connection']??'待检测'); ?></strong><p>检测时间：<?php echo esc_html(qcgeo_time($s['connection_at']??0)); ?></p></div>
    <div><span>公开内容目录</span><strong><?php echo esc_html($count); ?> 条</strong><p>文章、页面及公开自定义内容；不含分类归档。</p></div>
    <div><span>自动同步</span><strong><?php echo !$o['auto']?'未开启':(!empty($s['blocked'])?'已暂停，需处理错误':'已开启'); ?></strong><p>内容变更后排队，每15分钟补检。</p></div></div>
    <?php if(!empty($s['error'])): ?><div class="notice notice-error inline"><p><?php echo esc_html($s['error']); ?></p></div><?php endif; ?>
    <p>上次成功导入：<strong><?php echo esc_html(qcgeo_time($s['last_success']??0)); ?></strong> · 上次完整目录：<?php echo esc_html($s['count']??0); ?> 条</p>
    <p>最近核对：<?php echo esc_html(qcgeo_time($s['last_check']??0)); ?> · 下次计划：<?php echo esc_html(qcgeo_time(wp_next_scheduled('qcgeo_periodic'))); ?></p>
    <div class="qc-actions">
    <?php foreach(array('test'=>'测试连接','sync'=>'立即同步') as $a=>$label): ?><form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
    <?php wp_nonce_field('qcgeo_action'); ?><input type="hidden" name="action" value="qcgeo_action"><input type="hidden" name="qcgeo_action" value="<?php echo esc_attr($a); ?>"><button type="submit" class="button <?php echo $a==='sync'?'button-primary':''; ?>"><?php echo esc_html($label); ?></button></form><?php endforeach; ?>
    </div><p class="qc-detail">按钮使用已保存的配置。测试连接验证登录及网站读取权限；立即同步还会核验目录写入结果。定时任务由 WordPress 访问触发，低流量时可能延迟。</p></div>
    <div class="qc-panel"><h2>连接设置</h2><form method="post" action="options.php"><?php settings_fields('qcgeo'); ?>
    <table class="form-table" role="presentation"><tbody>
    <?php foreach(array('url'=>'平台 HTTPS 地址','id'=>'网站 UUID','username'=>'GEOInflow 账号') as $k=>$label): ?><tr><th><label for="qcgeo-<?php echo esc_attr($k); ?>"><?php echo esc_html($label); ?></label></th><td><input id="qcgeo-<?php echo esc_attr($k); ?>" class="regular-text" name="qcgeo_options[<?php echo esc_attr($k); ?>]" value="<?php echo esc_attr($o[$k]); ?>" <?php echo $k==='username'?'autocomplete="username"':'required'; ?>></td></tr><?php endforeach; ?>
    <tr><th><label for="qcgeo-password">GEOInflow 密码</label></th><td><input id="qcgeo-password" type="password" class="regular-text" name="qcgeo_options[password]" value="" autocomplete="new-password"><p class="description"><?php echo $o['secret']?'已保存，留空保持不变。':'尚未保存凭据。'; ?> 使用 WordPress 安全密钥加密保存。建议使用仅能管理此站点的专用账号；不要填写宝塔或服务器密码。</p><label><input type="checkbox" name="qcgeo_options[clear_secret]" value="1">清除已保存密码</label></td></tr>
    <tr><th>自动维护</th><td><label><input type="checkbox" name="qcgeo_options[auto]" value="1" <?php checked($o['auto'],1); ?>>启用文章和页面自动同步</label><p class="description">只同步公开内容元数据；不发送正文、用户信息、草稿或密码保护内容。</p></td></tr>
    </tbody></table><?php submit_button('保存连接设置'); ?></form></div>
    <div class="qc-panel"><h2>采集与兼容性</h2><ul>
    <li>浏览统计：<?php echo file_exists(WPMU_PLUGIN_DIR.'/geoinflow-tracker.php')?'由原有 MU 插件提供，本插件不重复注入。修改此处 ID 不会修改旧 MU 脚本。':($o['id']?'由本插件全站注入；实际入库需在平台回读。':'待填写网站 ID。'); ?></li>
    <li>目录接口：<a href="<?php echo esc_url(rest_url('qiancheng-geo/v1/catalog')); ?>">查看公开目录 JSON</a></li>
    <li>下线内容：WordPress 目录会自动排除；当前平台仅支持新增和更新，不支持自动清理旧 URL。已检测到本连接器历史同步中 <?php echo esc_html($s['removed']??0); ?> 条待核对。</li>
    <li>服务器日志采集、AI 模型和业务转化目标需分别配置，不由此插件自动开启。</li>
    </ul></div></div>
    <?php
}
add_action('wp_head',function(){
    $o=qcgeo_options();if(is_admin() || is_preview() || !$o['id'] || file_exists(WPMU_PLUGIN_DIR.'/geoinflow-tracker.php'))return;
    echo '<script defer src="'.esc_url($o['url'].'/script.js').'" data-website-id="'.esc_attr($o['id']).'"></script>'."\n";
},20);
function qcgeo_catalog($request) {
    $page=max(1,(int)$request->get_param('page'));
    $q=new WP_Query(array('post_type'=>array_values(array_diff(get_post_types(array('public'=>true)), array('attachment'))), 'post_status'=>'publish','has_password'=>false,'posts_per_page'=>100,'paged'=>$page,'orderby'=>'ID','order'=>'ASC','ignore_sticky_posts'=>true));
    $rows=array();
    foreach ($q->posts as $p) {
        if ($p->post_type==='attachment' || !is_post_publicly_viewable($p)) continue;
        $url=get_permalink($p);
        if (!$url || wp_parse_url($url,PHP_URL_HOST)!==wp_parse_url(home_url(),PHP_URL_HOST)) continue;
        $row=array('url'=>$url,'title'=>wp_strip_all_tags(get_the_title($p)),'type'=>$p->post_type,'source'=>'wordpress');
        foreach(array('publishedAt'=>'post_date_gmt','updatedAt'=>'post_modified_gmt') as $field=>$property) {
            if ($p->$property && $p->$property!=='0000-00-00 00:00:00') $row[$field]=str_replace(' ','T',$p->$property).'Z';
        }
        $rows[]=$row;
    }
    $r=new WP_REST_Response(array('schemaVersion'=>1,'site'=>home_url('/'),'page'=>$page,'pages'=>(int)$q->max_num_pages,'items'=>$rows));
    $r->header('Cache-Control','no-store');return $r;
}
add_action('rest_api_init',function () {
    register_rest_route('qiancheng-geo/v1','/catalog',array('methods'=>'GET','callback'=>'qcgeo_catalog','permission_callback'=>'__return_true','args'=>array('page'=>array('default'=>1,'sanitize_callback'=>'absint'))));
});

// Statistics are fetched server-side; credentials never enter the browser.
function qcgeo_report($days=7) {
    $days=in_array((int)$days,array(1,7,30),true)?(int)$days:7;
    $token=qcgeo_test();
    if(is_wp_error($token))return $token;
    $end=time();$start=(new DateTimeImmutable('today',wp_timezone()))->modify('-'.($days-1).' days')->getTimestamp();
    $query=http_build_query(array('startAt'=>$start*1000,'endAt'=>$end*1000,'timezone'=>wp_timezone_string()));
    $result=qcgeo_http('/api/websites/'.rawurlencode(qcgeo_options()['id']).'/stats?'.$query,'GET',null,$token);
    if(is_wp_error($result))return $result;
    if(!isset($result['pageviews']) || !is_numeric($result['pageviews']))return new WP_Error('schema','统计接口格式不兼容，不能显示为零。');
    return array('values'=>$result,'start'=>$start,'end'=>$end);
}
add_action('admin_menu',function(){add_menu_page('GEOInflow 网站统计','GEOInflow 统计','manage_options','qcgeo-stats','qcgeo_stats_admin','dashicons-chart-area',80);});
function qcgeo_stats_admin(){
    if(!current_user_can('manage_options'))return;
    $days=isset($_GET['days'])?absint($_GET['days']):7;
    if(!in_array($days,array(1,7,30),true))$days=7;
    echo '<div class="wrap"><h1>GEOInflow 网站统计</h1><p>本站数据由 GEOInflow 计算；页面浏览、访客和服务器请求分别统计。打开页面时读取，未授权或接口错误不显示为零。</p><p>';
    foreach(array(1=>'今天',7=>'近7天',30=>'近30天') as $n=>$label)echo '<a class="button" href="'.esc_url(admin_url('admin.php?page=qcgeo-stats&days='.$n)).'">'.esc_html($label).'</a> ';
    echo '</p>';
    $report=qcgeo_report($days);
    if(is_wp_error($report)){echo '<div class="notice notice-error inline"><p>'.esc_html($report->get_error_message()).'</p></div>';}
    else {
        echo '<p>统计时区：'.esc_html(wp_timezone_string()).' · '.esc_html(qcgeo_time($report['start'])).' 至 '.esc_html(qcgeo_time($report['end'])).'</p><table class="widefat striped"><tbody>';
        foreach(array('pageviews'=>'页面浏览 PV','visitors'=>'访客','visits'=>'访问次数','bounces'=>'跳出访问') as $key=>$label){
            $value=$report['values'][$key]??null;
            echo '<tr><th>'.esc_html($label).'</th><td>'.esc_html(is_numeric($value)?number_format_i18n($value):'未提供').'</td></tr>';
        }
        echo '</tbody></table>';
    }
    echo '<h2>全站接入</h2><ol><li>在连接设置中填写平台 HTTPS 地址、本站 UUID 和专用账号。</li><li>测试连接，核对网站域名；统计脚本会在支持 wp_head 的公开页面加载，已有 geoinflow-tracker.php 时不重复注入。</li><li>启用并验证内容目录同步；新安装不补造历史浏览数据。</li><li>需要爬虫和服务器状态码时，在网站服务器配置独立日志采集器。已有采集器先检查，不重复安装。</li></ol>';
    echo '<p><a class="button button-primary" href="'.esc_url(admin_url('options-general.php?page=qcgeo')).'">连接与同步设置</a></p>';
    $o=qcgeo_options();
    if($o['id'])echo '<p><a target="_blank" rel="noopener noreferrer" href="'.esc_url($o['url'].'/websites/'.rawurlencode($o['id']).'/geo').'">打开本站完整统计与服务器接入引导</a></p>';
    echo '<p>Cloudflare 日志、服务器日志、手动导入的覆盖范围不同。服务器一次安装命令须由平台按本站生成；插件不执行服务器命令。AI 引荐不等于 AI 引用或成交。</p></div>';
}
