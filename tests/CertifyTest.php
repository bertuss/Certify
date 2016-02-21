<?php

namespace bertuss\Certify\Test;

use bertuss\Certify\Certify;
use bertuss\Certify\Exceptions\Unparseable;

class CertifyTest extends \PHPUnit_Framework_TestCase
{

    public function testExampleComCertificateIsValid()
    {
        $certify = new Certify('example.com');

        $this->assertTrue($certify->isPopulated());
        $this->assertTrue($certify->isValid());
    }


    public function testUnparseableException()
    {
        $this->expectException(\bertuss\Certify\Exceptions\Unparseable::class);
        $this->expectExceptionMessage('Parse failure');

        $certify = new Certify('http://:80');
    }

}
