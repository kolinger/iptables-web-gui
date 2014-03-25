<?php

require_once __DIR__ . '/lib/SSH.php';
require_once __DIR__ . '/lib/Iptables.php';

$ssh = new SSH('192.168.20.127');
$ssh->setUsername('root');
$ssh->setPassword('root');

$iptables = new Iptables($ssh);
$iptables->setOnFly(FALSE);

$flashes = array();
$editDialogDisplayed = FALSE;
$editDialogAction = './index.php';

function buildQueryFromRule(\stdClass $rule, $table, $chain)
{
	$rule = clone $rule;
	$parameters = array();
	$parameters['protocol'] = $rule->protocol;
	$parameters['in'] = $rule->in;
	$parameters['out'] = $rule->out;
	$parameters['source'] = $rule->source;
	$parameters['destination'] = $rule->destination;
	$parameters['target'] = $rule->target;
	if (preg_match('~--(d|s)port ([0-9:]+)~i', $rule->additional, $matches)) {
		$parameters[$matches[1] . 'port'] = $matches[2];
		$rule->additional = str_replace($matches[0], '', $rule->additional);
	}
	$parameters['additional'] = trim($rule->additional);
	$parameters['table'] = $table;
	$parameters['chain'] = $chain;
	return http_build_query($parameters);
}

function buildRuleFromQuery()
{
	$rule = new \stdClass();
	$rule->in = isset($_GET['in']) ? $_GET['in'] : '';
	$rule->out = isset($_GET['out']) ? $_GET['out'] : '';
	$rule->source = isset($_GET['source']) ? $_GET['source'] : '';
	$rule->destination = isset($_GET['destination']) ? $_GET['destination'] : '';
	$rule->protocol = isset($_GET['protocol']) ? $_GET['protocol'] : '';
	$rule->dport = isset($_GET['dport']) ? $_GET['dport'] : '';
	$rule->sport = isset($_GET['sport']) ? $_GET['sport'] : '';
	$rule->additional = isset($_GET['additional']) ? trim($_GET['additional']) : '';
	$rule->target = isset($_GET['target']) ? $_GET['target'] : '';
	return $rule;
}

if (isset($_GET['reload'])) {
	session_start();
	unset($_SESSION[Iptables::$sessionCacheKey]);
	header('Location: index.php');
}

if (isset($_GET['export'])) {
	header('Content-Type: application/octet-stream');
	header('Content-Disposition: attachment; filename="iptables-export.conf"');
	echo $iptables->export();
	exit;
}

if (isset($_GET['import'])) {
	if (!isset($_FILES['file']) || $_FILES['file']['error'] == UPLOAD_ERR_NO_FILE) {
		$flashes['danger'][] = 'No file selected';
	} else {
		$content = file_get_contents($_FILES['file']['tmp_name']);
		$output = $iptables->import($content);
		if ($output) {
			$flashes['danger'][] = $output;
		} else {
			$flashes['success'][] = 'File successfully imported';
		}
		header('Location: index.php');
	}
}

if (isset($_GET['edit'])) {
	$editDialogDisplayed = TRUE;
	$table = $_GET['table'];
	$chain = $_GET['chain'];
	$rule = buildRuleFromQuery();
	$editDialogAction .= '?edit&' . buildQueryFromRule($rule, $table, $chain);
}

if (isset($_GET['add'])) {
	$editDialogDisplayed = TRUE;
}

include __DIR__ . '/template.phtml';