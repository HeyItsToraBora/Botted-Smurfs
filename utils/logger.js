const winston = require('winston');
const config = require('../config');
const fetch = require('node-fetch');

const logger = winston.createLogger({
    level: config.LOG_LEVEL,
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' })
    ]
});

if (config.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
        )
    }));
}

// Send a log message to Discord via webhook
async function sendDiscordEmbed(type, action, details, user = 'System') {
    const webhookUrl = config.DISCORD_WEBHOOK_URL;
    // Define colors for different log types
    const colors = {
        info: 3447003,    // Blue
        success: 5763719,  // Green
        warning: 16776960, // Yellow
        error: 15158332    // Red
    };
    let embed = {
        title: action,
        description: details,
        color: colors[type] || colors.info,
        timestamp: new Date().toISOString(),
        footer: {
            text: `User: ${user}`
        }
    };
    // Add fields based on action type
    switch(action) {
        case 'Account Created':
            embed.fields = [
                { name: 'Action', value: 'Account Creation', inline: true },
                { name: 'Status', value: 'Success', inline: true }
            ];
            break;
        case 'Account Deleted':
            embed.fields = [
                { name: 'Action', value: 'Account Deletion', inline: true },
                { name: 'Status', value: 'Warning', inline: true }
            ];
            break;
        case 'Account Status Changed':
            embed.fields = [
                { name: 'Action', value: 'Status Change', inline: true },
                { name: 'Status', value: 'Warning', inline: true }
            ];
            break;
        case 'Offer Updated':
            embed.fields = [
                { name: 'Action', value: 'Offer Update', inline: true },
                { name: 'Status', value: 'Success', inline: true }
            ];
            break;
        case 'Coupon Updated':
            embed.fields = [
                { name: 'Action', value: 'Coupon Update', inline: true },
                { name: 'Status', value: 'Success', inline: true }
            ];
            break;
        default:
            if (type === 'error') {
                embed.fields = [
                    { name: 'Action', value: action, inline: true },
                    { name: 'Status', value: 'Error', inline: true }
                ];
            }
    }
    try {
        await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ embeds: [embed] })
        });
    } catch (err) {
        logger.error('Error sending Discord webhook:', err);
    }
}

module.exports = logger; 
module.exports.sendDiscordEmbed = sendDiscordEmbed; 