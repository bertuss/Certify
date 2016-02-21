<?php

namespace bertuss\Certify;

class Certify
{
    private $host;
    private $url;
    private $certificate;
    private $populated;
    private $serialNumber;
    private $commonName;
    private $validFrom;
    private $validTo;
    private $signatureType;
    private $issuer;

    /**
     * Certify constructor.
     * @param $url
     */
    public function __construct($url)
    {
        $this->url = $this->parseUrl($url);

        $this->populated = false;

        $this->certificate = $this->retrieveCertificate();

        if (is_array($this->certificate)) {
            $this->populateAttributes($this->certificate);
        }

    }

    /**
     * @param $url
     * @return string
     * @throws Exceptions\Unparseable
     */
    private function parseUrl($url)
    {
        $urlComponents = parse_url($url);

        if (!is_array($urlComponents)) {
            throw new Exceptions\Unparseable("Parse failure");
        }

        if (array_key_exists('host', $urlComponents)) {
            return $this->formatUrl($urlComponents['host']);
        }

        if (array_key_exists('path', $urlComponents)) {
            return $this->formatUrl($urlComponents['path']);
        }

        throw new Exceptions\Unparseable("Invalid URL");
    }

    /**
     * @param $host
     * @return string
     */
    private function formatUrl($host)
    {
        return sprintf('ssl://%s:443/', $host);
    }

    /**
     * @return array
     */
    private function retrieveCertificate()
    {
        $context = stream_context_create(
            [
                'ssl' => [
                    'capture_peer_cert' => true,
                    'capture_peer_cert_chain' => true,
                    'allow_self_signed' => true,
                ]
            ]
        );

        $errno = -1;
        $errstr = '#';

        $client = stream_socket_client(
            $this->url,
            $errno,
            $errstr,
            10,
            STREAM_CLIENT_CONNECT,
            $context
        );

        $contextParams = stream_context_get_params($client);

        return openssl_x509_parse($contextParams["options"]["ssl"]["peer_certificate"], false);
    }

    /**
     * @param array $certificate
     */
    private function populateAttributes(Array $certificate)
    {
        $this->populated = true;

        if (array_key_exists('serialNumber', $certificate)) {
            $this->serialNumber = $certificate['serialNumber'];
        }

        if (array_key_exists('subject', $certificate)) {
            if (array_key_exists('commonName', $certificate['subject'])) {
                $this->commonName = $certificate['subject']['commonName'];
            }
        }

        if (array_key_exists('validFrom_time_t', $certificate)) {
            $this->validFrom = new \DateTime('@' . $certificate['validFrom_time_t']);
        }

        if (array_key_exists('validTo_time_t', $certificate)) {
            $this->validTo = new \DateTime('@' . $certificate['validTo_time_t']);
        }

        if (array_key_exists('signatureTypeSN', $certificate)) {
            $this->signatureType = $certificate['signatureTypeSN'];
        }

        if (array_key_exists('issuer', $certificate)) {
            if (array_key_exists('commonName', $certificate['issuer'])) {
                $this->issuer = $certificate['issuer']['commonName'];
            }
        }
    }

    public function getSerialNumber()
    {
        return $this->serialNumber;
    }

    public function getCommonName()
    {
        return $this->commonName;
    }

    public function getValidFrom()
    {
        return $this->validFrom;
    }

    public function getValidTo()
    {
        return $this->validTo;
    }

    public function getSignatureType()
    {
        return $this->signatureType;
    }

    public function getIssuer()
    {
        return $this->issuer;
    }

    public function isPopulated()
    {
        return $this->populated;
    }

    public function isValidOn(\DateTime $date)
    {
        return (boolean)($date >= $this->validFrom AND $date <= $this->validTo);
    }

    public function isValid()
    {
        return $this->isValidOn(new \DateTime('now'));
    }

    public function expiresInNextMonth()
    {
        return !$this->isValidOn(new \DateTime('+1 month'));
    }

}
