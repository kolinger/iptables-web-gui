<?php

/**
 * @author Tomáš Kolinger <tomas@kolinger.name>
 */
class Iptables
{

	const MODE_IP4 = 0;
	const MODE_IP6 = 1;
	const MODE_HYBRID = 2;

	/**
	 * @var string
	 */
	public static $sessionCacheKey = 'iptables-cache';

	/**
	 * @var string
	 */
	private $ip4executable = 'iptables';

	/**
	 * @var string
	 */
	private $ip6executable = 'ip6tables';

	/**
	 * @var SSH
	 */
	private $ssh;

	/**
	 * @var int
	 */
	private $mode = self::MODE_HYBRID;

	/**
	 * @var array
	 */
	private $tables;

	/**
	 * @var boolean
	 */
	private $onFly = TRUE;


	/**
	 * @param SSH $ssh
	 */
	public function __construct(SSH $ssh)
	{
		$this->ssh = $ssh;
	}


	/**
	 * @param string $ip4executable
	 */
	public function setIp4executable($ip4executable)
	{
		$this->ip4executable = $ip4executable;
	}


	/**
	 * @return string
	 */
	public function getIp4executable()
	{
		return $this->ip4executable;
	}


	/**
	 * @param string $ip6executable
	 */
	public function setIp6executable($ip6executable)
	{
		$this->ip6executable = $ip6executable;
	}


	/**
	 * @return string
	 */
	public function getIp6executable()
	{
		return $this->ip6executable;
	}


	/**
	 * @param int $mode
	 */
	public function setMode($mode)
	{
		$this->mode = $mode;
	}


	/**
	 * @return int
	 */
	public function getMode()
	{
		return $this->mode;
	}


	/**
	 * @param array $tables
	 */
	public function setTables($tables)
	{
		$this->tables = $tables;
	}


	/**
	 * @return array
	 */
	public function getTables()
	{
		if ($this->tables === NULL) {
			if (!$this->onFly) {
				if (session_id() === '') {
					session_start();
				}
				if (isset($_SESSION[static::$sessionCacheKey]) && is_array($_SESSION[static::$sessionCacheKey])) {
					$this->tables = $_SESSION[static::$sessionCacheKey];
				} else {
					$this->parseTables();
					$_SESSION[static::$sessionCacheKey] = $this->tables;
				}
			} else {
				$this->parseTables();
			}
		}
		return $this->tables;
	}


	/**
	 * @param boolean $onFly
	 */
	public function setOnFly($onFly)
	{
		$this->onFly = $onFly;
	}


	/**
	 * @return boolean
	 */
	public function getOnFly()
	{
		return $this->onFly;
	}


	/**
	 * @return string
	 */
	public function export()
	{
		return $this->ssh->execute($this->ip4executable . '-save');
	}


	/**
	 * @todo what about command injection?
	 * @param string $configuration
	 * @return string
	 */
	public function import($configuration)
	{
		return $this->ssh->execute($this->ip4executable . '-restore --test <<< "' . $configuration . '"');
	}


	/**
	 * @param \stdClass $rule
	 * @param string $table
	 * @param string $chain
	 */
	public function add(\stdClass $rule, $table, $chain)
	{
		$parameters = $this->buildParameters($rule);
		var_dump($parameters);
	}


	/**
	 * @param \stdClass $rule
	 * @param string $table
	 * @param string $chain
	 */
	public function remove(\stdClass $rule, $table, $chain)
	{
		$parameters = $this->buildParameters($rule);
		var_dump($parameters);
	}


	private function parseTables()
	{
		$this->tables = array();

		// filter
		$this->parseChain('INPUT');
		$this->parseChain('FORWARD');
		$this->parseChain('OUTPUT');

		// nat
		$this->parseChain('PREROUTING', 'nat');
		$this->parseChain('OUTPUT', 'nat');
		$this->parseChain('POSTROUTING', 'nat');
	}


	/**
	 * @param string $chain
	 * @param string $table
	 * @throws \Exception
	 */
	private function parseChain($chain, $table = 'filter')
	{
		if ($table) {
			$parameters = '-L ' . $chain . ' -t ' . $table . ' -n -v';
		} else {
			$parameters = '-L ' . $chain . ' -n -v';
		}
		$output = $this->executeIp4iptables($parameters);
		if (!preg_match('~Chain [a-z]+ \(policy ([a-z]+)~i', $output, $matches)) {
			throw new \Exception('Executing of iptables with parameters ' . $parameters . ' failed, got wrong
				output: ' . $output);
		}

		$this->tables[$table][$chain]['policy'] = $matches[1];
		$this->tables[$table][$chain]['rules'] = array();

		$lines = explode("\n", $output);

		// columns positions, must be in right order!
		$columns = array(
			'target' => strpos($lines[1], 'target'),
			'prot' => strpos($lines[1], 'prot'),
			'opt' => strpos($lines[1], 'opt'),
			'in' => strpos($lines[1], 'in'),
			'out' => strpos($lines[1], 'out'),
			'source' => strpos($lines[1], 'source'),
			'destination' => strpos($lines[1], 'destination')
		);

		$columns = array_reverse($columns); // first column must be last

		array_shift($lines); // strip headline
		array_shift($lines); // strip table header
		array_pop($lines); // strip last blank line

		// parse tables
		foreach ($lines as $line) {
			$rule = new \stdClass();
			$previous = strlen($line);
			foreach ($columns as $name => $position) {
				$rule->$name = trim(substr($line, $position, $previous - $position));
				$previous = $position;
				if ($name === 'destination') { // last column - need check for additional parameters
					$delimiter = strpos($rule->$name, '  ');
					if ($delimiter !== FALSE) {
						$rule->misc = trim(substr($rule->$name, $delimiter, strlen($rule->$name)));
						$rule->$name = trim(substr($rule->$name, 0, $delimiter));
					}
				}
			}
			$this->tables[$table][$chain]['rules'][] = $this->formatRule($rule);
		}
	}


	/**
	 * @param stdClass $rule
	 * @return stdClass
	 */
	private function formatRule(\stdClass $rule)
	{
		if ($rule->prot === 'all') {
			$rule->prot = '';
		}

		if ($rule->opt === '--') {
			$rule->opt = '';
		}

		if ($rule->in === '*') {
			$rule->in = '';
		}

		if ($rule->out === '*') {
			$rule->out = '';
		}


		if ($rule->source === '0.0.0.0/0') {
			$rule->source = '';
		}


		if ($rule->destination === '0.0.0.0/0') {
			$rule->destination = '';
		}

		if (!isset($rule->misc)) {
			$rule->misc = '';
		} else {
			// remove ambiguous protocol
			$rule->misc = preg_replace('~(?:tcp|udp) ((?:d|s)pts?:[0-9:]+)~i', '\\1', $rule->misc);
		}

		return $rule;
	}


	/**
	 * @param stdClass $rule
	 * @return string
	 */
	private function buildParameters(\stdClass $rule)
	{
		$parameters = array();
		if ($rule->prot) {
			$parameters[] = '-p ' . $rule->prot;
		}

		if ($rule->in) {
			$parameters[] = '-i ' . $rule->in;
		}

		if ($rule->out) {
			$parameters[] = '-o ' . $rule->out;
		}

		if ($rule->source) {
			$parameters[] = '-s ' . $rule->source;
		}

		if ($rule->destination) {
			$parameters[] = '-d ' . $rule->destination;
		}

		if ($rule->misc) {
			$parts = explode(' ', $rule->misc);
			$count = count($parts);
			for ($index = 0; $index < $count; $index += 2) {
				$parameters[] = (strlen($parts[$index]) == 1 ? '-' : '--') . $parts[$index] . ' ' . $parts[$index + 1];
			}
		}

		if (isset($rule->additional)) {
			$parameters[] = $rule->additional;
		}

		return implode(' ', $parameters);
	}


	/**
	 * @param string $parameters
	 * @return string
	 */
	private function executeIp4iptables($parameters)
	{
		return $this->ssh->execute($this->ip4executable . ' ' . $parameters);
	}


	/**
	 * @param string $parameters
	 * @return string
	 */
	private function executeIp6iptables($parameters)
	{
		return $this->ssh->execute($this->ip6executable . ' ' . $parameters);
	}
}