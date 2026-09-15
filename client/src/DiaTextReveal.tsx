import { animate, motion, useInView, useMotionValue, useReducedMotion, useTransform } from 'motion/react'
import { useEffect, useRef } from 'react'

const BAND_HALF = 17

function gradient(position: number, colors: string[], textColor: string) {
  const start = position - BAND_HALF
  const end = position + BAND_HALF
  if (start >= 100) return `linear-gradient(90deg, ${textColor}, ${textColor})`

  const points = start > 0 ? [textColor, `${textColor} ${start.toFixed(2)}%`] : []
  colors.forEach((color, index) => {
    points.push(`${color} ${(start + (index / Math.max(colors.length - 1, 1)) * BAND_HALF * 2).toFixed(2)}%`)
  })
  if (end < 100) points.push(`transparent ${end.toFixed(2)}%`, 'transparent 100%')
  return `linear-gradient(90deg, ${points.join(', ')})`
}

export function DiaTextReveal({
  text,
  colors = ['#2597d0', '#d7e6f5', '#2597d0'],
  textColor = 'var(--blue)',
  duration = 1.6,
  delay = 0.15,
  className,
}: {
  text: string
  colors?: string[]
  textColor?: string
  duration?: number
  delay?: number
  className?: string
}) {
  const ref = useRef<HTMLSpanElement>(null)
  const isInView = useInView(ref, { once: true, amount: 0.1 })
  const prefersReducedMotion = useReducedMotion()
  const position = useMotionValue(-BAND_HALF)
  const backgroundImage = useTransform(position, (value) => gradient(value, colors, textColor))

  useEffect(() => {
    if (prefersReducedMotion || !isInView) {
      position.set(117)
      return
    }

    const controls = animate(position, 117, {
      delay,
      duration,
      ease: [0.25, 0.8, 0.25, 1],
    })
    return () => controls.stop()
  }, [delay, duration, isInView, prefersReducedMotion, position])

  return (
    <motion.span
      ref={ref}
      className={className}
      style={{
        color: 'transparent',
        backgroundClip: 'text',
        WebkitBackgroundClip: 'text',
        backgroundImage,
        backgroundSize: '100% 100%',
      }}
    >
      {text}
    </motion.span>
  )
}
