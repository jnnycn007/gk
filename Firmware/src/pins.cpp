#include <stm32h7rsxx.h>

#include "pins.h"
#include "gk_conf.h"

INTFLASH_FUNCTION void pin_set(const struct pin &p, int mode, int ospeed, int af, int otype, int pup)
{
    GPIO_TypeDef *gpio = p.gpio;

    if(gpio == GPIOA)
    {
        RCC->AHB4ENR |= RCC_AHB4ENR_GPIOAEN;
        (void)RCC->AHB4ENR;
    }
    else if(gpio == GPIOB)
    {
        RCC->AHB4ENR |= RCC_AHB4ENR_GPIOBEN;
        (void)RCC->AHB4ENR;
    }
    else if(gpio == GPIOC)
    {
        RCC->AHB4ENR |= RCC_AHB4ENR_GPIOCEN;
        (void)RCC->AHB4ENR;
    }
    else if(gpio == GPIOD)
    {
        RCC->AHB4ENR |= RCC_AHB4ENR_GPIODEN;
        (void)RCC->AHB4ENR;
    }
    else if(gpio == GPIOE)
    {
        RCC->AHB4ENR |= RCC_AHB4ENR_GPIOEEN;
        (void)RCC->AHB4ENR;
    }
    else if(gpio == GPIOF)
    {
        RCC->AHB4ENR |= RCC_AHB4ENR_GPIOFEN;
        (void)RCC->AHB4ENR;
    }
    else if(gpio == GPIOG)
    {
        RCC->AHB4ENR |= RCC_AHB4ENR_GPIOGEN;
        (void)RCC->AHB4ENR;
    }
    else if(gpio == GPIOH)
    {
        RCC->AHB4ENR |= RCC_AHB4ENR_GPIOHEN;
        (void)RCC->AHB4ENR;
    }
    else if(gpio == GPIOM)
    {
        RCC->AHB4ENR |= RCC_AHB4ENR_GPIOMEN;
        (void)RCC->AHB4ENR;
    }
    else if(gpio == GPION)
    {
        RCC->AHB4ENR |= RCC_AHB4ENR_GPIONEN;
        (void)RCC->AHB4ENR;
    }
    else if(gpio == GPIOO)
    {
        RCC->AHB4ENR |= RCC_AHB4ENR_GPIOOEN;
        (void)RCC->AHB4ENR;
    }
    else if(gpio == GPIOP)
    {
        RCC->AHB4ENR |= RCC_AHB4ENR_GPIOPEN;
        (void)RCC->AHB4ENR;
    }

    int pin = p.pin;

    gpio->MODER &= ~(3UL << (pin * 2));
    gpio->MODER |= (mode << (pin * 2));

    /* limit GPIOC13/14/15 speed */
    if(gpio == GPIOC && ((pin == 13) || (pin == 14) || (pin == 15)))
        ospeed = 0;

    gpio->OSPEEDR &= ~(3UL << (pin * 2));
    gpio->OSPEEDR |= (ospeed << (pin * 2));
    if(pin < 8)
    {
        gpio->AFR[0] &= ~(15UL << (pin * 4));
        gpio->AFR[0] |= (af << (pin * 4));
    }
    else
    {
        gpio->AFR[1] &= ~(15UL << ((pin - 8) * 4));
        gpio->AFR[1] |= (af << ((pin - 8) * 4));
    }
    gpio->OTYPER &= ~(1UL << pin);
    gpio->OTYPER |= (otype << pin);

    gpio->PUPDR &= ~(3UL << (pin * 2));
    gpio->PUPDR |= (pup << (pin * 2));
}

INTFLASH_FUNCTION void pin::set() const
{
    gpio->BSRR = 1UL << pin;
}

INTFLASH_FUNCTION void pin::clear() const
{
    gpio->BSRR = 1UL << (pin + 16);
}

INTFLASH_FUNCTION bool pin::value() const
{
    return (gpio->IDR & (1UL << pin)) != 0;
}

INTFLASH_FUNCTION void pin::set_as_af(otype _otype, pup _pup, int af_override) const
{
    pin_set(*this, 2, 3, af_override == -1 ? af : af_override,
        (int)_otype, (int)_pup);
}

INTFLASH_FUNCTION void pin::set_as_output(otype _otype, pup _pup) const
{
    pin_set(*this, 1, 3, 0, (int)_otype, (int)_pup);
}

INTFLASH_FUNCTION void pin::set_as_input(pup _pup) const
{
    pin_set(*this, 0, 3, 0, 0, (int)_pup);
}
