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

/**
 * @param \stdClass $rule
 * @param string $table
 * @param string $chain
 * @return string
 */
function buildQueryFromRule(\stdClass $rule, $table, $chain) {
	$rule = clone $rule;
	$parameters = array();
	$parameters['prot'] = $rule->prot;
	$parameters['in'] = $rule->in;
	$parameters['out'] = $rule->out;
	$parameters['source'] = $rule->source;
	$parameters['destination'] = $rule->destination;
	$parameters['target'] = $rule->target;
	if (preg_match('~(d|s)pts?:([0-9:]+)~i', $rule->misc, $matches)) {
		$parameters[$matches[1] . 'port'] = $matches[2];
		$rule->misc = str_replace($matches[0], '', $rule->misc);
	}
	$parameters['additional'] = preg_replace('~ ([a-z]{1,1} [a-z0-9]+)~i', '-\\1', ' ' . $rule->misc);
	$parameters['additional'] = trim(preg_replace('~ ([a-z]{2,} [a-z0-9]+)~i', '--\\1', $parameters['additional']));
	$parameters['additional'] = str_replace('--state', '-m state --state', $parameters['additional']); // TODO: how to fix this generally for all these arguments?
	$parameters['table'] = $table;
	$parameters['chain'] = $chain;
	return http_build_query($parameters);
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
}

if (isset($_GET['add'])) {
	$editDialogDisplayed = TRUE;
}

include __DIR__ . '/template.phtml';