<?php

/**
 * @author Tomáš Kolinger <tomas@kolinger.name>
 */
class Iptables
{

	/**
	 * @var string
	 */
	public static $sessionCacheKey = 'iptables-cache';

	/**
	 * @var string
	 */
	private $executable = 'iptables';

	/**
	 * @var SSH
	 */
	private $ssh;

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
	public function setExecutable($ip4executable)
	{
		$this->executable = $ip4executable;
	}


	/**
	 * @return string
	 */
	public function getExecutable()
	{
		return $this->executable;
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
		return $this->ssh->execute($this->executable . '-save');
	}


	/**
	 * @todo what about command injection?
	 * @param string $configuration
	 * @return string
	 */
	public function import($configuration)
	{
		return $this->ssh->execute($this->executable . '-restore --test <<< "' . $configuration . '"');
	}


	/**
	 * @param \stdClass $rule
	 * @param string $table
	 * @param string $chain
	 * @return string
	 */
	public function add(\stdClass $rule, $table, $chain)
	{
		$parameters = '-t ' . $table . ' -A ' . $chain . ' ';
		$parameters .= $this->buildParameters($rule);
		return $this->execute($parameters);
	}


	/**
	 * @param \stdClass $rule
	 * @param string $table
	 * @param string $chain
	 * @return string
	 */
	public function remove(\stdClass $rule, $table, $chain)
	{
		$parameters = '-t ' . $table . ' -D ' . $chain . ' ';
		$parameters .= $this->buildParameters($rule);
		return $this->execute($parameters);
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
		$output = $this->execute($parameters);
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
			'protocol' => strpos($lines[1], 'prot'),
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
						$rule->additional = trim(substr($rule->$name, $delimiter, strlen($rule->$name)));
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
		if ($rule->protocol === 'all') {
			$rule->protocol = '';
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

		if (!isset($rule->additional)) {
			$rule->additional = '';
		} else {
			// format ports
			$rule->additional = preg_replace('~(?:tcp|udp) (?:(d|s)pts?:([0-9:]+))~i', '\\1port \\2', $rule->additional);

			// add dashes
			$rule->additional = preg_replace('~ ([a-z]{1,1})(?: |:)([a-z0-9]+)~i', ' -\\1 \\2', ' ' . $rule->additional);
			$rule->additional = trim(preg_replace('~ ([a-z]{2,})(?: |:)([a-z0-9]+)~i', ' --\\1 \\2', $rule->additional));

			// fix state
			$rule->additional = str_replace('--state', '-m state --state', $rule->additional);
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
		if ($rule->protocol) {
			$parameters[] = '-p ' . $rule->protocol;
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

		if ($rule->additional) {
			$parameters[] = trim($rule->additional);
		}

		if ($rule->target) {
			$parameters[] = '-j ' . $rule->target;
		}

		return implode(' ', $parameters);
	}


	/**
	 * @param string $parameters
	 * @return string
	 */
	private function execute($parameters)
	{
		return $this->ssh->execute($this->executable . ' ' . $parameters);
	}
}