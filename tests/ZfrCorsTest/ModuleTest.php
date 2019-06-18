<?php
/*
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This software consists of voluntary contributions made by many individuals
 * and is licensed under the MIT license.
 */

namespace ZfrCorsTest;

use PHPUnit\Framework\TestCase;
use ZfrCors\Module;

/**
 * Tests for {@see \ZfrCors\Module}
 *
 * @license MIT
 * @author  Marco Pivetta <ocramius@gmail.com>
 *
 * @group Coverage
 */
class ModuleTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @covers \ZfrCors\Module::getConfig
     */
    public function testGetConfig()
    {
        $module = new Module();

        $this->assertInternalType('array', $module->getConfig());
        $this->assertSame($module->getConfig(), unserialize(serialize($module->getConfig())), 'Config is serializable');
    }

    /**
     * @covers \ZfrCors\Module::onBootstrap
     */
    public function testAssertListenerIsCorrectlyRegistered()
    {
        $module         = new Module();
        $mvcEvent       = $this->getMockBuilder('Zend\Mvc\MvcEvent')->getMock();
        $application    = $this->getMockBuilder('Zend\Mvc\Application', [], [], '', false)
            ->disableOriginalConstructor()
            ->getMock();
        $eventManager   = $this->getMockBuilder('Zend\EventManager\EventManagerInterface')->getMock();
        $serviceManager = $this->getMockBuilder('Zend\ServiceManager\ServiceManager')->getMock();
        $corsListener   = $this->getMockBuilder('ZfrCors\Mvc\CorsRequestListener', [], [], '', false)
            ->disableOriginalConstructor()
            ->getMock();

        $mvcEvent->expects($this->any())->method('getTarget')->will($this->returnValue($application));
        $application->expects($this->any())->method('getEventManager')->will($this->returnValue($eventManager));
        $application->expects($this->any())->method('getServiceManager')->will($this->returnValue($serviceManager));
        $serviceManager
            ->expects($this->any())
            ->method('get')
            ->with('ZfrCors\Mvc\CorsRequestListener')
            ->will($this->returnValue($corsListener));

        $corsListener->expects($this->once())->method('attach')->with($eventManager);

        $module->onBootstrap($mvcEvent);
    }
}
