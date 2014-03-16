<?php

/**
 * @author Tomáš Kolinger <tomas@kolinger.name>
 */
class SSH
{

	/**
	 * @var resource
	 */
	private $connection;

	/**
	 * @var string
	 */
	private $host;

	/**
	 * @var int
	 */
	private $port;

	/**
	 * @var string
	 */
	private $username;

	/**
	 * @var string
	 */
	private $password;

	/**
	 * @var string
	 */
	private $publicKey;

	/**
	 * @var string
	 */
	private $privateKey;

	/**
	 * @var string
	 */
	private $passPhrase;


	/**
	 * @param string $host
	 * @param int $port
	 */
	public function __construct($host = 'localhost', $port = 22)
	{
		$this->host = $host;
		$this->port = $port;
	}


	/**
	 * @param string $password
	 */
	public function setPassword($password)
	{
		$this->password = $password;
	}


	/**
	 * @param string $username
	 */
	public function setUsername($username)
	{
		$this->username = $username;
	}


	/**
	 * @param string $public
	 * @param string $private
	 * @param string $passPhrase
	 */
	public function setKeys($public, $private, $passPhrase = NULL)
	{
		$this->publicKey = $public;
		$this->privateKey = $private;
		$this->passPhrase = $passPhrase;
	}


	public function connect()
	{
		$this->connection = ssh2_connect($this->host, $this->port);

		if ($this->username && $this->publicKey && $this->privateKey) {
			ssh2_auth_pubkey_file($this->connection, $this->username, $this->publicKey, $this->privateKey,
				$this->passPhrase);
		} else {
			if ($this->username && $this->password) {
				ssh2_auth_password($this->connection, $this->username, $this->password);
			} else {
				throw new \Exception('No authentication method specified - use setUsername and setPassword for password
				based authentication or setUsername and setKeys for key based authentication');
			}
		}
	}


	/**
	 * @return resource
	 */
	public function getConnection()
	{
		if ($this->connection === NULL) {
			$this->connect();
		}
		return $this->connection;
	}


	/**
	 * @param string $command
	 * @return string
	 */
	public function execute($command)
	{
		$outputStream = ssh2_exec($this->getConnection(), $command);
		$errorStream = ssh2_fetch_stream($outputStream, SSH2_STREAM_STDERR);

		stream_set_blocking($errorStream, TRUE);
		stream_set_blocking($outputStream, TRUE);

		$output = stream_get_contents($outputStream);
		$error = stream_get_contents($errorStream);

		fclose($outputStream);
		fclose($errorStream);

		return $output ?: $error;
	}
}