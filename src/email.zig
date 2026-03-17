const std = @import("std");
const net = std.net;
const crypto = std.crypto;

pub const EmailConfig = struct {
    smtp_host: []const u8,
    smtp_port: u16 = 587,
    username: []const u8,
    password: []const u8,
    from_address: []const u8,
    use_tls: bool = true,
};

pub const EmailMessage = struct {
    to: []const u8,
    subject: []const u8,
    body_text: []const u8,
    body_html: ?[]const u8 = null,
    reply_to: ?[]const u8 = null,
};

// SMTP client for sending emails
pub const SmtpClient = struct {
    allocator: std.mem.Allocator,
    config: EmailConfig,
    stream: ?net.Stream = null,

    pub fn init(allocator: std.mem.Allocator, config: EmailConfig) SmtpClient {
        return SmtpClient{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn deinit(self: *SmtpClient) void {
        if (self.stream) |*stream| {
            stream.close();
        }
    }

    // Send an email
    pub fn sendEmail(self: *SmtpClient, message: EmailMessage) !void {
        try self.connect();
        defer self.disconnect();

        try self.authenticate();
        try self.sendMessage(message);
    }

    fn connect(self: *SmtpClient) !void {
        const address = try net.Address.parseIp(self.config.smtp_host, self.config.smtp_port);
        self.stream = try net.tcpConnectToAddress(address);

        // Read greeting
        var buffer: [1024]u8 = undefined;
        const greeting = try self.readResponse(&buffer);
        if (!std.mem.startsWith(u8, greeting, "220")) {
            return error.SmtpError;
        }

        // Send EHLO
        try self.sendCommand("EHLO localhost\r\n");
        const ehlo_response = try self.readResponse(&buffer);
        if (!std.mem.startsWith(u8, ehlo_response, "250")) {
            return error.SmtpError;
        }

        // Start TLS if required
        if (self.config.use_tls) {
            try self.startTls();
        }
    }

    fn authenticate(self: *SmtpClient) !void {
        // Send AUTH LOGIN
        try self.sendCommand("AUTH LOGIN\r\n");
        var buffer: [1024]u8 = undefined;
        var response = try self.readResponse(&buffer);
        if (!std.mem.startsWith(u8, response, "334")) {
            return error.AuthError;
        }

        // Send username (base64 encoded)
        const username_b64 = try self.base64Encode(self.config.username);
        defer self.allocator.free(username_b64);
        try self.sendCommand(try std.fmt.allocPrint(self.allocator, "{s}\r\n", .{username_b64}));
        response = try self.readResponse(&buffer);
        if (!std.mem.startsWith(u8, response, "334")) {
            return error.AuthError;
        }

        // Send password (base64 encoded)
        const password_b64 = try self.base64Encode(self.config.password);
        defer self.allocator.free(password_b64);
        try self.sendCommand(try std.fmt.allocPrint(self.allocator, "{s}\r\n", .{password_b64}));
        response = try self.readResponse(&buffer);
        if (!std.mem.startsWith(u8, response, "235")) {
            return error.AuthError;
        }
    }

    fn sendMessage(self: *SmtpClient, message: EmailMessage) !void {
        var buffer: [1024]u8 = undefined;

        // Send MAIL FROM
        try self.sendCommand(try std.fmt.allocPrint(self.allocator, "MAIL FROM:<{s}>\r\n", .{self.config.from_address}));
        var response = try self.readResponse(&buffer);
        if (!std.mem.startsWith(u8, response, "250")) {
            return error.SmtpError;
        }

        // Send RCPT TO
        try self.sendCommand(try std.fmt.allocPrint(self.allocator, "RCPT TO:<{s}>\r\n", .{message.to}));
        response = try self.readResponse(&buffer);
        if (!std.mem.startsWith(u8, response, "250")) {
            return error.SmtpError;
        }

        // Send DATA
        try self.sendCommand("DATA\r\n");
        response = try self.readResponse(&buffer);
        if (!std.mem.startsWith(u8, response, "354")) {
            return error.SmtpError;
        }

        // Send email content
        const email_content = try self.formatEmail(message);
        defer self.allocator.free(email_content);

        try self.sendCommand(email_content);
        try self.sendCommand("\r\n.\r\n");

        response = try self.readResponse(&buffer);
        if (!std.mem.startsWith(u8, response, "250")) {
            return error.SmtpError;
        }
    }

    fn formatEmail(self: *SmtpClient, message: EmailMessage) ![]u8 {
        var email = std.array_list.Managed(u8).init(self.allocator);
        defer email.deinit();

        // Headers
        try email.writer().print("From: {s}\r\n", .{self.config.from_address});
        try email.writer().print("To: {s}\r\n", .{message.to});
        try email.writer().print("Subject: {s}\r\n", .{message.subject});

        if (message.reply_to) |reply_to| {
            try email.writer().print("Reply-To: {s}\r\n", .{reply_to});
        }

        // Content-Type
        if (message.body_html) |_| {
            try email.writer().writeAll("Content-Type: multipart/alternative; boundary=\"boundary123\"\r\n\r\n");
            try email.writer().writeAll("--boundary123\r\n");
            try email.writer().writeAll("Content-Type: text/plain; charset=UTF-8\r\n\r\n");
            try email.writer().writeAll(message.body_text);
            try email.writer().writeAll("\r\n\r\n--boundary123\r\n");
            try email.writer().writeAll("Content-Type: text/html; charset=UTF-8\r\n\r\n");
            try email.writer().writeAll(message.body_html.?);
            try email.writer().writeAll("\r\n\r\n--boundary123--");
        } else {
            try email.writer().writeAll("Content-Type: text/plain; charset=UTF-8\r\n\r\n");
            try email.writer().writeAll(message.body_text);
        }

        return email.toOwnedSlice();
    }

    fn startTls(_: *SmtpClient) !void {
        // For now, skip TLS implementation (would need crypto library integration)
        // In production, you'd establish TLS connection here
    }

    fn sendCommand(self: *SmtpClient, command: []const u8) !void {
        if (self.stream) |*stream| {
            _ = try stream.write(command);
        } else {
            return error.NotConnected;
        }
    }

    fn readResponse(self: *SmtpClient, buffer: []u8) ![]u8 {
        if (self.stream) |*stream| {
            const bytes_read = try stream.read(buffer);
            if (bytes_read == 0) return error.ConnectionClosed;

            // Find end of response (ends with \r\n)
            var end: usize = 0;
            for (buffer[0..bytes_read], 0..) |byte, i| {
                if (i >= 1 and buffer[i - 1] == '\r' and byte == '\n') {
                    end = i + 1;
                    break;
                }
            }

            return buffer[0..end];
        } else {
            return error.NotConnected;
        }
    }

    fn base64Encode(self: *SmtpClient, input: []const u8) ![]u8 {
        const encoded_len = std.base64.standard.Encoder.calcSize(input.len);
        const encoded = try self.allocator.alloc(u8, encoded_len);
        _ = std.base64.standard.Encoder.encode(encoded, input);
        return encoded;
    }

    fn disconnect(self: *SmtpClient) !void {
        if (self.stream) |*stream| {
            try self.sendCommand("QUIT\r\n");
            stream.close();
            self.stream = null;
        }
    }
};

// Email template system
pub const EmailTemplates = struct {
    pub fn welcomeEmail(username: []const u8, verification_link: ?[]const u8) EmailMessage {
        const subject = "Welcome to Speedy Socials!";
        var body_text = std.fmt.allocPrint(std.heap.page_allocator, "Welcome {s}!\n\nThank you for joining Speedy Socials. Your account has been created successfully.\n\n", .{username}) catch "Welcome!";

        if (verification_link) |link| {
            body_text = std.fmt.allocPrint(std.heap.page_allocator, "{s}Please verify your email by clicking this link: {s}\n\n", .{ body_text, link }) catch body_text;
        }

        body_text = std.fmt.allocPrint(std.heap.page_allocator, "{s}Happy posting!\n\nThe Speedy Socials Team", .{body_text}) catch body_text;

        return EmailMessage{
            .to = "", // Set by caller
            .subject = subject,
            .body_text = body_text,
        };
    }

    pub fn passwordResetEmail(username: []const u8, reset_link: []const u8) EmailMessage {
        const subject = "Password Reset - Speedy Socials";
        const body_text = std.fmt.allocPrint(std.heap.page_allocator, "Hi {s},\n\nYou requested a password reset for your Speedy Socials account.\n\nClick this link to reset your password: {s}\n\nThis link will expire in 1 hour.\n\nIf you didn't request this, please ignore this email.\n\nThe Speedy Socials Team", .{ username, reset_link }) catch "Password reset requested.";

        return EmailMessage{
            .to = "", // Set by caller
            .subject = subject,
            .body_text = body_text,
        };
    }

    pub fn mentionNotificationEmail(username: []const u8, mentioner: []const u8, post_url: []const u8) EmailMessage {
        const subject = std.fmt.allocPrint(std.heap.page_allocator, "{s} mentioned you on Speedy Socials", .{mentioner}) catch "You were mentioned";

        const body_text = std.fmt.allocPrint(std.heap.page_allocator, "Hi {s},\n\n{s} mentioned you in a post.\n\nView it here: {s}\n\nThe Speedy Socials Team", .{ username, mentioner, post_url }) catch "You were mentioned in a post.";

        return EmailMessage{
            .to = "", // Set by caller
            .subject = subject,
            .body_text = body_text,
        };
    }

    pub fn followNotificationEmail(username: []const u8, follower: []const u8) EmailMessage {
        const subject = std.fmt.allocPrint(std.heap.page_allocator, "{s} started following you", .{follower}) catch "New follower";

        const body_text = std.fmt.allocPrint(std.heap.page_allocator, "Hi {s},\n\n{s} started following you on Speedy Socials.\n\nThe Speedy Socials Team", .{ username, follower }) catch "You have a new follower.";

        return EmailMessage{
            .to = "", // Set by caller
            .subject = subject,
            .body_text = body_text,
        };
    }

    pub fn likeNotificationEmail(username: []const u8, liker: []const u8, post_url: []const u8) EmailMessage {
        const subject = std.fmt.allocPrint(std.heap.page_allocator, "{s} liked your post", .{liker}) catch "Your post was liked";

        const body_text = std.fmt.allocPrint(std.heap.page_allocator, "Hi {s},\n\n{s} liked your post.\n\nView it here: {s}\n\nThe Speedy Socials Team", .{ username, liker, post_url }) catch "Your post was liked.";

        return EmailMessage{
            .to = "", // Set by caller
            .subject = subject,
            .body_text = body_text,
        };
    }
};

// Email service for managing SMTP connections
pub const EmailService = struct {
    allocator: std.mem.Allocator,
    config: EmailConfig,
    client: ?SmtpClient = null,

    pub fn init(allocator: std.mem.Allocator, config: EmailConfig) EmailService {
        return EmailService{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn deinit(self: *EmailService) void {
        if (self.client) |*client| {
            client.deinit();
        }
    }

    // Send an email
    pub fn send(self: *EmailService, message: EmailMessage) !void {
        var client = SmtpClient.init(self.allocator, self.config);
        defer client.deinit();

        try client.sendEmail(message);
    }

    // Send welcome email
    pub fn sendWelcomeEmail(self: *EmailService, to: []const u8, username: []const u8, verification_link: ?[]const u8) !void {
        var message = EmailTemplates.welcomeEmail(username, verification_link);
        message.to = to;

        try self.send(message);
    }

    // Send password reset email
    pub fn sendPasswordResetEmail(self: *EmailService, to: []const u8, username: []const u8, reset_link: []const u8) !void {
        var message = EmailTemplates.passwordResetEmail(username, reset_link);
        message.to = to;

        try self.send(message);
    }

    // Send notification emails
    pub fn sendMentionNotification(self: *EmailService, to: []const u8, username: []const u8, mentioner: []const u8, post_url: []const u8) !void {
        var message = EmailTemplates.mentionNotificationEmail(username, mentioner, post_url);
        message.to = to;

        try self.send(message);
    }

    pub fn sendFollowNotification(self: *EmailService, to: []const u8, username: []const u8, follower: []const u8) !void {
        var message = EmailTemplates.followNotificationEmail(username, follower);
        message.to = to;

        try self.send(message);
    }

    pub fn sendLikeNotification(self: *EmailService, to: []const u8, username: []const u8, liker: []const u8, post_url: []const u8) !void {
        var message = EmailTemplates.likeNotificationEmail(username, liker, post_url);
        message.to = to;

        try self.send(message);
    }
};

// Default email configuration (for development)
pub fn createDefaultEmailConfig(allocator: std.mem.Allocator) !EmailConfig {
    return EmailConfig{
        .smtp_host = try allocator.dupe(u8, "smtp.gmail.com"), // Example
        .smtp_port = 587,
        .username = try allocator.dupe(u8, "your-email@gmail.com"),
        .password = try allocator.dupe(u8, "your-app-password"),
        .from_address = try allocator.dupe(u8, "noreply@speedy-socials.local"),
        .use_tls = true,
    };
}
