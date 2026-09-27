/* Shared Chart.js theme helpers.
 * Reads CSS custom properties from the active theme so charts stay consistent
 * with the rest of the UI and re-render correctly when the theme changes.
 */
(function() {
    'use strict';

    function readVar(name, fallback) {
        var value = getComputedStyle(document.body).getPropertyValue(name).trim();
        return value || fallback;
    }

    function hexToRgb(hex) {
        var m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
        if (!m) return null;
        return {
            r: parseInt(m[1], 16),
            g: parseInt(m[2], 16),
            b: parseInt(m[3], 16)
        };
    }

    function luminance(rgb) {
        var a = [rgb.r, rgb.g, rgb.b].map(function(v) {
            v /= 255;
            return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
        });
        return a[0] * 0.2126 + a[1] * 0.7152 + a[2] * 0.0722;
    }

    function isLightTheme() {
        var bg = readVar('--bg', '#0f172a');
        var rgb = hexToRgb(bg);
        if (!rgb) {
            // Fallback: check for known light theme classes
            return document.body.classList.contains('light-theme') ||
                   document.body.classList.contains('theme-catppuccin-latte');
        }
        return luminance(rgb) > 0.5;
    }

    window.getChartThemeColors = function() {
        var light = isLightTheme();
        return {
            text: readVar('--text', light ? '#1e293b' : '#e2e8f0'),
            textHeading: readVar('--text-heading', light ? '#0f172a' : '#f1f5f9'),
            textMuted: readVar('--text-muted', light ? '#64748b' : '#94a3b8'),
            gridLine: readVar('--chart-grid', light ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.05)'),
            chartLine: readVar('--chart-line', '#3b82f6'),
            chartLineFill: readVar('--chart-line-fill', 'rgba(59,130,246,0.1)'),
            bgCard: readVar('--bg-card', light ? '#ffffff' : '#1e293b'),
            borderColor: readVar('--border', light ? 'rgba(0,0,0,0.2)' : 'rgba(255,255,255,0.15)'),
            isLight: light
        };
    };

    window.getChartPalette = function() {
        var colors = [];
        for (var i = 0; i < 12; i++) {
            var c = readVar('--chart-palette-' + i, '');
            if (c) colors.push(c);
        }
        if (colors.length === 0) {
            colors = [
                '#3b82f6', '#ef4444', '#22c55e', '#f59e0b', '#8b5cf6',
                '#ec4899', '#06b6d4', '#84cc16', '#f97316', '#6366f1',
                '#14b8a6', '#a855f7'
            ];
        }
        return colors;
    };

    window.getSemanticColors = function() {
        return {
            success: readVar('--success', '#22c55e'),
            warning: readVar('--warning', '#f59e0b'),
            danger: readVar('--danger', '#ef4444')
        };
    };

    window.colorWithAlpha = function(color, alpha) {
        var rgb = hexToRgb(color);
        if (!rgb) {
            /* Try to parse rgb(...) / rgba(...) strings. */
            var m = color.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
            if (m) {
                rgb = { r: parseInt(m[1], 10), g: parseInt(m[2], 10), b: parseInt(m[3], 10) };
            }
        }
        if (!rgb) return color;
        return 'rgba(' + rgb.r + ', ' + rgb.g + ', ' + rgb.b + ', ' + alpha + ')';
    };

    window.isLightTheme = isLightTheme;
})();
