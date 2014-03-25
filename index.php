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

function buildRuleFromQuery(array $array)
{
	$rule = new \stdClass();
	$rule->in = isset($array['in']) ? $array['in'] : '';
	$rule->out = isset($array['out']) ? $array['out'] : '';
	$rule->source = isset($array['source']) ? $array['source'] : '';
	$rule->destination = isset($array['destination']) ? $array['destination'] : '';
	$rule->protocol = isset($array['protocol']) ? $array['protocol'] : '';
	$rule->additional = isset($array['additional']) ? trim($array['additional']) : '';
	if (isset($array['dport']) && $array['dport']) {
		$rule->additional .= ' --dport ' . $array['dport'];
	}
	if (isset($array['sport']) && $array['sport']) {
		$rule->additional .= ' --sport ' . $array['sport'];
	}
	$rule->target = isset($array['target']) ? $array['target'] : '';
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

if (isset($_GET['remove'])) {
	$rule = buildRuleFromQuery($_GET);
	$iptables->remove($rule, $_GET['table'], $_GET['chain']);
}

if (isset($_GET['edit'])) {
	$editDialogDisplayed = TRUE;
	$rule = buildRuleFromQuery($_GET);
	$editDialogAction .= '?edit&' . buildQueryFromRule($rule, $_GET['table'], $_GET['chain']);
	if (isset($_POST['submit'])) {
		$iptables->remove($rule, $_GET['table'], $_GET['chain']);
		$newRule = buildRuleFromQuery($_POST);
		$iptables->add($newRule, $_POST['table'], $_POST['chain']);
	}
}

if (isset($_GET['add'])) {
	$editDialogDisplayed = TRUE;
	$editDialogAction .= '?add';
	if (isset($_POST['submit'])) {
		$rule = buildRuleFromQuery($_POST);
		$iptables->add($rule, $_POST['table'], $_POST['chain']);
	}
}

include __DIR__ . '/template.phtml';