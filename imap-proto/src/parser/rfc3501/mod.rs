//!
//! https://tools.ietf.org/html/rfc3501
//!
//! INTERNET MESSAGE ACCESS PROTOCOL
//!

use std::borrow::Cow;
use std::str::from_utf8;

use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case, take_while, take_while1},
    character::streaming::char,
    combinator::{map, map_res, opt, recognize, value},
    multi::{many0, many1, separated_list1},
    sequence::{delimited, pair, preceded, terminated, tuple},
    IResult,
};

use crate::{
    parser::{
        core::*, rfc2087, rfc2971, rfc3501::body::*, rfc3501::body_structure::*, rfc4314, rfc4315,
        rfc4551, rfc5161, rfc5256, rfc5464, rfc7162,
    },
    types::*,
};

use super::gmail;

pub mod body;
pub mod body_structure;

fn is_tag_char(c: u8) -> bool {
    c != b'+' && is_astring_char(c)
}

fn status_ok(i: &[u8]) -> IResult<&[u8], Status> {
    map(tag_no_case("OK"), |_s| Status::Ok)(i)
}
fn status_no(i: &[u8]) -> IResult<&[u8], Status> {
    map(tag_no_case("NO"), |_s| Status::No)(i)
}
fn status_bad(i: &[u8]) -> IResult<&[u8], Status> {
    map(tag_no_case("BAD"), |_s| Status::Bad)(i)
}
fn status_preauth(i: &[u8]) -> IResult<&[u8], Status> {
    map(tag_no_case("PREAUTH"), |_s| Status::PreAuth)(i)
}
fn status_bye(i: &[u8]) -> IResult<&[u8], Status> {
    map(tag_no_case("BYE"), |_s| Status::Bye)(i)
}

fn status(i: &[u8]) -> IResult<&[u8], Status> {
    alt((status_ok, status_no, status_bad, status_preauth, status_bye))(i)
}

pub(crate) fn mailbox(i: &[u8]) -> IResult<&[u8], &str> {
    map(astring_utf8, |s| {
        if s.eq_ignore_ascii_case("INBOX") {
            "INBOX"
        } else {
            s
        }
    })(i)
}

fn flag_extension(i: &[u8]) -> IResult<&[u8], &str> {
    map_res(
        recognize(pair(tag(b"\\"), take_while(is_atom_char))),
        from_utf8,
    )(i)
}

pub(crate) fn flag(i: &[u8]) -> IResult<&[u8], &str> {
    // Correct code is
    //   alt((flag_extension, atom))(i)
    //
    // Unfortunately, some unknown providers send the following response:
    // * FLAGS (OIB-Seen-[Gmail]/All)
    //
    // As a workaround, ']' (resp-specials) is allowed here.
    alt((
        flag_extension,
        map_res(take_while1(is_astring_char), from_utf8),
    ))(i)
}

fn flag_list(i: &[u8]) -> IResult<&[u8], Vec<Cow<str>>> {
    // Correct code is
    //   parenthesized_list(flag)(i)
    //
    // Unfortunately, Zoho Mail Server (imap.zoho.com) sends the following response:
    // * FLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)
    //
    // As a workaround, "\*" is allowed here.
    parenthesized_list(map(flag_perm, Cow::Borrowed))(i)
}

fn flag_perm(i: &[u8]) -> IResult<&[u8], &str> {
    alt((map_res(tag(b"\\*"), from_utf8), flag))(i)
}

fn resp_text_code_alert(i: &[u8]) -> IResult<&[u8], ResponseCode> {
    map(tag_no_case(b"ALERT"), |_| ResponseCode::Alert)(i)
}

fn resp_text_code_badcharset(i: &[u8]) -> IResult<&[u8], ResponseCode> {
    map(
        preceded(
            tag_no_case(b"BADCHARSET"),
            opt(preceded(
                tag(b" "),
                parenthesized_nonempty_list(map(astring_utf8, Cow::Borrowed)),
            )),
        ),
        ResponseCode::BadCharset,
    )(i)
}

fn resp_text_code_capability(i: &[u8]) -> IResult<&[u8], ResponseCode> {
    map(capability_data, ResponseCode::Capabilities)(i)
}

fn resp_text_code_parse(i: &[u8]) -> IResult<&[u8], ResponseCode> {
    map(tag_no_case(b"PARSE"), |_| ResponseCode::Parse)(i)
}

fn resp_text_code_permanent_flags(i: &[u8]) -> IResult<&[u8], ResponseCode> {
    map(
        preceded(
            tag_no_case(b"PERMANENTFLAGS "),
            parenthesized_list(map(flag_perm, Cow::Borrowed)),
        ),
        ResponseCode::PermanentFlags,
    )(i)
}

fn resp_text_code_read_only(i: &[u8]) -> IResult<&[u8], ResponseCode> {
    map(tag_no_case(b"READ-ONLY"), |_| ResponseCode::ReadOnly)(i)
}

fn resp_text_code_read_write(i: &[u8]) -> IResult<&[u8], ResponseCode> {
    map(tag_no_case(b"READ-WRITE"), |_| ResponseCode::ReadWrite)(i)
}

fn resp_text_code_try_create(i: &[u8]) -> IResult<&[u8], ResponseCode> {
    map(tag_no_case(b"TRYCREATE"), |_| ResponseCode::TryCreate)(i)
}

fn resp_text_code_uid_validity(i: &[u8]) -> IResult<&[u8], ResponseCode> {
    map(
        preceded(tag_no_case(b"UIDVALIDITY "), number),
        ResponseCode::UidValidity,
    )(i)
}

fn resp_text_code_uid_next(i: &[u8]) -> IResult<&[u8], ResponseCode> {
    map(
        preceded(tag_no_case(b"UIDNEXT "), number),
        ResponseCode::UidNext,
    )(i)
}

fn resp_text_code_unseen(i: &[u8]) -> IResult<&[u8], ResponseCode> {
    map(
        preceded(tag_no_case(b"UNSEEN "), number),
        ResponseCode::Unseen,
    )(i)
}

fn resp_text_code(i: &[u8]) -> IResult<&[u8], ResponseCode> {
    // Per the spec, the closing tag should be "] ".
    // See `resp_text` for more on why this is done differently.
    delimited(
        tag(b"["),
        alt((
            resp_text_code_alert,
            resp_text_code_badcharset,
            resp_text_code_capability,
            resp_text_code_parse,
            resp_text_code_permanent_flags,
            resp_text_code_uid_validity,
            resp_text_code_uid_next,
            resp_text_code_unseen,
            resp_text_code_read_only,
            resp_text_code_read_write,
            resp_text_code_try_create,
            rfc4551::resp_text_code_highest_mod_seq,
            rfc4315::resp_text_code_append_uid,
            rfc4315::resp_text_code_copy_uid,
            rfc4315::resp_text_code_uid_not_sticky,
            rfc5464::resp_text_code_metadata_long_entries,
            rfc5464::resp_text_code_metadata_max_size,
            rfc5464::resp_text_code_metadata_too_many,
            rfc5464::resp_text_code_metadata_no_private,
        )),
        tag(b"]"),
    )(i)
}

fn capability(i: &[u8]) -> IResult<&[u8], Capability> {
    alt((
        map(tag_no_case(b"IMAP4rev1"), |_| Capability::Imap4rev1),
        map(
            map(preceded(tag_no_case(b"AUTH="), atom), Cow::Borrowed),
            Capability::Auth,
        ),
        map(map(atom, Cow::Borrowed), Capability::Atom),
    ))(i)
}

fn ensure_capabilities_contains_imap4rev(
    capabilities: Vec<Capability<'_>>,
) -> Result<Vec<Capability<'_>>, ()> {
    if capabilities.contains(&Capability::Imap4rev1) {
        Ok(capabilities)
    } else {
        Err(())
    }
}

fn capability_data(i: &[u8]) -> IResult<&[u8], Vec<Capability>> {
    map_res(
        preceded(
            tag_no_case(b"CAPABILITY"),
            many0(preceded(char(' '), capability)),
        ),
        ensure_capabilities_contains_imap4rev,
    )(i)
}

fn mailbox_data_search(i: &[u8]) -> IResult<&[u8], MailboxDatum> {
    map(
        // Technically, trailing whitespace is not allowed here, but multiple
        // email servers in the wild seem to have it anyway (see #34, #108).
        terminated(
            preceded(tag_no_case(b"SEARCH"), many0(preceded(tag(" "), number))),
            opt(tag(" ")),
        ),
        MailboxDatum::Search,
    )(i)
}

fn mailbox_data_flags(i: &[u8]) -> IResult<&[u8], MailboxDatum> {
    map(
        preceded(tag_no_case("FLAGS "), flag_list),
        MailboxDatum::Flags,
    )(i)
}

fn mailbox_data_exists(i: &[u8]) -> IResult<&[u8], MailboxDatum> {
    map(
        terminated(number, tag_no_case(" EXISTS")),
        MailboxDatum::Exists,
    )(i)
}

fn name_attribute(i: &[u8]) -> IResult<&[u8], NameAttribute> {
    alt((
        // RFC 3501
        value(NameAttribute::NoInferiors, tag_no_case(b"\\Noinferiors")),
        value(NameAttribute::NoSelect, tag_no_case(b"\\Noselect")),
        value(NameAttribute::Marked, tag_no_case(b"\\Marked")),
        value(NameAttribute::Unmarked, tag_no_case(b"\\Unmarked")),
        // RFC 6154
        value(NameAttribute::All, tag_no_case(b"\\All")),
        value(NameAttribute::Archive, tag_no_case(b"\\Archive")),
        value(NameAttribute::Drafts, tag_no_case(b"\\Drafts")),
        value(NameAttribute::Flagged, tag_no_case(b"\\Flagged")),
        value(NameAttribute::Junk, tag_no_case(b"\\Junk")),
        value(NameAttribute::Sent, tag_no_case(b"\\Sent")),
        value(NameAttribute::Trash, tag_no_case(b"\\Trash")),
        // Extensions not supported by this crate
        map(
            map_res(
                recognize(pair(tag(b"\\"), take_while(is_atom_char))),
                from_utf8,
            ),
            |s| NameAttribute::Extension(Cow::Borrowed(s)),
        ),
    ))(i)
}

#[allow(clippy::type_complexity)]
fn mailbox_list(i: &[u8]) -> IResult<&[u8], (Vec<NameAttribute>, Option<&str>, &str)> {
    map(
        tuple((
            parenthesized_list(name_attribute),
            tag(b" "),
            alt((map(quoted_utf8, Some), map(nil, |_| None))),
            tag(b" "),
            mailbox,
        )),
        |(name_attributes, _, delimiter, _, name)| (name_attributes, delimiter, name),
    )(i)
}

fn mailbox_data_list(i: &[u8]) -> IResult<&[u8], MailboxDatum> {
    map(preceded(tag_no_case("LIST "), mailbox_list), |data| {
        MailboxDatum::List {
            name_attributes: data.0,
            delimiter: data.1.map(Cow::Borrowed),
            name: Cow::Borrowed(data.2),
        }
    })(i)
}

fn mailbox_data_lsub(i: &[u8]) -> IResult<&[u8], MailboxDatum> {
    map(preceded(tag_no_case("LSUB "), mailbox_list), |data| {
        MailboxDatum::List {
            name_attributes: data.0,
            delimiter: data.1.map(Cow::Borrowed),
            name: Cow::Borrowed(data.2),
        }
    })(i)
}

// Unlike `status_att` in the RFC syntax, this includes the value,
// so that it can return a valid enum object instead of just a key.
fn status_att(i: &[u8]) -> IResult<&[u8], StatusAttribute> {
    alt((
        rfc4551::status_att_val_highest_mod_seq,
        map(
            preceded(tag_no_case("MESSAGES "), number),
            StatusAttribute::Messages,
        ),
        map(
            preceded(tag_no_case("RECENT "), number),
            StatusAttribute::Recent,
        ),
        map(
            preceded(tag_no_case("UIDNEXT "), number),
            StatusAttribute::UidNext,
        ),
        map(
            preceded(tag_no_case("UIDVALIDITY "), number),
            StatusAttribute::UidValidity,
        ),
        map(
            preceded(tag_no_case("UNSEEN "), number),
            StatusAttribute::Unseen,
        ),
    ))(i)
}

fn status_att_list(i: &[u8]) -> IResult<&[u8], Vec<StatusAttribute>> {
    // RFC 3501 specifies that the list is non-empty in the formal grammar
    //   status-att-list =  status-att SP number *(SP status-att SP number)
    // but mail.163.com sends an empty list in STATUS response anyway.
    parenthesized_list(status_att)(i)
}

fn mailbox_data_status(i: &[u8]) -> IResult<&[u8], MailboxDatum> {
    map(
        tuple((tag_no_case("STATUS "), mailbox, tag(" "), status_att_list)),
        |(_, mailbox, _, status)| MailboxDatum::Status {
            mailbox: Cow::Borrowed(mailbox),
            status,
        },
    )(i)
}

fn mailbox_data_recent(i: &[u8]) -> IResult<&[u8], MailboxDatum> {
    map(
        terminated(number, tag_no_case(" RECENT")),
        MailboxDatum::Recent,
    )(i)
}

fn mailbox_data(i: &[u8]) -> IResult<&[u8], MailboxDatum> {
    alt((
        mailbox_data_flags,
        mailbox_data_exists,
        mailbox_data_list,
        mailbox_data_lsub,
        mailbox_data_status,
        mailbox_data_recent,
        mailbox_data_search,
        gmail::mailbox_data_gmail_labels,
        gmail::mailbox_data_gmail_msgid,
        rfc5256::mailbox_data_sort,
    ))(i)
}

// An address structure is a parenthesized list that describes an
// electronic mail address.
fn address(i: &[u8]) -> IResult<&[u8], Address> {
    paren_delimited(map(
        tuple((
            nstring,
            tag(" "),
            nstring,
            tag(" "),
            nstring,
            tag(" "),
            nstring,
        )),
        |(name, _, adl, _, mailbox, _, host)| Address {
            name: name.map(Cow::Borrowed),
            adl: adl.map(Cow::Borrowed),
            mailbox: mailbox.map(Cow::Borrowed),
            host: host.map(Cow::Borrowed),
        },
    ))(i)
}

fn opt_addresses(i: &[u8]) -> IResult<&[u8], Option<Vec<Address>>> {
    alt((
        map(nil, |_s| None),
        map(
            paren_delimited(many1(terminated(address, opt(char(' '))))),
            Some,
        ),
    ))(i)
}

// envelope        = "(" env-date SP env-subject SP env-from SP
//                   env-sender SP env-reply-to SP env-to SP env-cc SP
//                   env-bcc SP env-in-reply-to SP env-message-id ")"
//
// env-bcc         = "(" 1*address ")" / nil
//
// env-cc          = "(" 1*address ")" / nil
//
// env-date        = nstring
//
// env-from        = "(" 1*address ")" / nil
//
// env-in-reply-to = nstring
//
// env-message-id  = nstring
//
// env-reply-to    = "(" 1*address ")" / nil
//
// env-sender      = "(" 1*address ")" / nil
//
// env-subject     = nstring
//
// env-to          = "(" 1*address ")" / nil
pub(crate) fn envelope(i: &[u8]) -> IResult<&[u8], Envelope> {
    paren_delimited(map(
        tuple((
            nstring,
            tag(" "),
            nstring,
            tag(" "),
            opt_addresses,
            tag(" "),
            opt_addresses,
            tag(" "),
            opt_addresses,
            tag(" "),
            opt_addresses,
            tag(" "),
            opt_addresses,
            tag(" "),
            opt_addresses,
            tag(" "),
            nstring,
            tag(" "),
            nstring,
        )),
        |(
            date,
            _,
            subject,
            _,
            from,
            _,
            sender,
            _,
            reply_to,
            _,
            to,
            _,
            cc,
            _,
            bcc,
            _,
            in_reply_to,
            _,
            message_id,
        )| Envelope {
            date: date.map(Cow::Borrowed),
            subject: subject.map(Cow::Borrowed),
            from,
            sender,
            reply_to,
            to,
            cc,
            bcc,
            in_reply_to: in_reply_to.map(Cow::Borrowed),
            message_id: message_id.map(Cow::Borrowed),
        },
    ))(i)
}

fn msg_att_envelope(i: &[u8]) -> IResult<&[u8], AttributeValue> {
    map(preceded(tag_no_case("ENVELOPE "), envelope), |envelope| {
        AttributeValue::Envelope(Box::new(envelope))
    })(i)
}

fn msg_att_envelope2(input: &[u8]) -> IResult<&[u8], AttributeValue2> {
    map(preceded(tag_no_case("ENVELOPE "), envelope), |_| {
        AttributeValue2::Ignored
    })(input)
}

fn msg_att_internal_date(i: &[u8]) -> IResult<&[u8], AttributeValue> {
    map(
        preceded(tag_no_case("INTERNALDATE "), nstring_utf8),
        |date| AttributeValue::InternalDate(Cow::Borrowed(date.unwrap())),
    )(i)
}

fn msg_att_internal_date2(input: &[u8]) -> IResult<&[u8], AttributeValue2> {
    map(preceded(tag_no_case("INTERNALDATE "), nstring_utf8), |_| {
        AttributeValue2::Ignored
    })(input)
}

fn msg_att_flags(i: &[u8]) -> IResult<&[u8], AttributeValue> {
    map(
        preceded(tag_no_case("FLAGS "), flag_list),
        AttributeValue::Flags,
    )(i)
}

fn msg_att_flags2(input: &[u8]) -> IResult<&[u8], AttributeValue2> {
    map(preceded(tag_no_case("FLAGS "), flag_list), |_| {
        AttributeValue2::Ignored
    })(input)
}

fn msg_att_rfc822(i: &[u8]) -> IResult<&[u8], AttributeValue> {
    map(preceded(tag_no_case("RFC822 "), nstring), |v| {
        AttributeValue::Rfc822(v.map(Cow::Borrowed))
    })(i)
}

fn msg_att_rfc822_2(input: &[u8]) -> IResult<&[u8], AttributeValue2> {
    map(preceded(tag_no_case("RFC822 "), nstring2), |_v| {
        AttributeValue2::Ignored
    })(input)
}

fn msg_att_rfc822_header(i: &[u8]) -> IResult<&[u8], AttributeValue> {
    // extra space workaround for DavMail
    map(
        tuple((tag_no_case("RFC822.HEADER "), opt(tag(b" ")), nstring)),
        |(_, _, raw)| AttributeValue::Rfc822Header(raw.map(Cow::Borrowed)),
    )(i)
}

fn msg_att_rfc822_header2(input: &[u8]) -> IResult<&[u8], AttributeValue2> {
    // extra space workaround for DavMail
    map(
        tuple((tag_no_case("RFC822.HEADER "), opt(tag(b" ")), nstring2)),
        |(_, _, (_data, size))| AttributeValue2::Rfc822Header(size),
    )(input)
}

fn msg_att_rfc822_size(i: &[u8]) -> IResult<&[u8], AttributeValue> {
    map(
        preceded(tag_no_case("RFC822.SIZE "), number),
        AttributeValue::Rfc822Size,
    )(i)
}

fn msg_att_rfc822_size2(input: &[u8]) -> IResult<&[u8], AttributeValue2> {
    map(preceded(tag_no_case("RFC822.SIZE "), number), |_| {
        AttributeValue2::Ignored
    })(input)
}

fn msg_att_rfc822_text(i: &[u8]) -> IResult<&[u8], AttributeValue> {
    map(preceded(tag_no_case("RFC822.TEXT "), nstring), |v| {
        AttributeValue::Rfc822Text(v.map(Cow::Borrowed))
    })(i)
}

fn msg_att_rfc822_text2(input: &[u8]) -> IResult<&[u8], AttributeValue2> {
    map(
        preceded(tag_no_case("RFC822.TEXT "), nstring2),
        |(_data, size)| AttributeValue2::Rfc822Text(size),
    )(input)
}

fn msg_att_uid(i: &[u8]) -> IResult<&[u8], AttributeValue> {
    map(preceded(tag_no_case("UID "), number), AttributeValue::Uid)(i)
}

fn msg_att_uid2(input: &[u8]) -> IResult<&[u8], AttributeValue2> {
    map(preceded(tag_no_case("UID "), number), |_| {
        AttributeValue2::Ignored
    })(input)
}

// msg-att         = "(" (msg-att-dynamic / msg-att-static)
//                    *(SP (msg-att-dynamic / msg-att-static)) ")"
//
// msg-att-dynamic = "FLAGS" SP "(" [flag-fetch *(SP flag-fetch)] ")"
//                     ; MAY change for a message
//
// msg-att-static  = "ENVELOPE" SP envelope / "INTERNALDATE" SP date-time /
//                   "RFC822" [".HEADER" / ".TEXT"] SP nstring /
//                   "RFC822.SIZE" SP number /
//                   "BODY" ["STRUCTURE"] SP body /
//                   "BODY" section ["<" number ">"] SP nstring /
//                   "UID" SP uniqueid
//                     ; MUST NOT change for a message
fn msg_att(i: &[u8]) -> IResult<&[u8], AttributeValue> {
    alt((
        msg_att_body_section,
        msg_att_body_structure,
        msg_att_envelope,
        msg_att_internal_date,
        msg_att_flags,
        rfc4551::msg_att_mod_seq,
        msg_att_rfc822,
        msg_att_rfc822_header,
        msg_att_rfc822_size,
        msg_att_rfc822_text,
        msg_att_uid,
        gmail::msg_att_gmail_labels,
        gmail::msg_att_gmail_msgid,
    ))(i)
}

fn msg_att2(input: &[u8]) -> IResult<&[u8], AttributeValue2> {
    alt((
        msg_att_body_section2,
        msg_att_body_structure2,
        msg_att_envelope2,
        msg_att_internal_date2,
        msg_att_flags2,
        rfc4551::msg_att_mod_seq2,
        msg_att_rfc822_2,
        msg_att_rfc822_header2,
        msg_att_rfc822_size2,
        msg_att_rfc822_text2,
        msg_att_uid2,
        gmail::msg_att_gmail_labels2,
        gmail::msg_att_gmail_msgid2,
    ))(input)
}

fn msg_att_list(i: &[u8]) -> IResult<&[u8], Vec<AttributeValue>> {
    parenthesized_nonempty_list(msg_att)(i)
}

// message-data    = nz-number SP ("EXPUNGE" / ("FETCH" SP msg-att))
fn message_data_fetch(i: &[u8]) -> IResult<&[u8], Response> {
    map(
        tuple((number, tag_no_case(" FETCH "), msg_att_list)),
        |(num, _, attrs)| Response::Fetch(num, attrs),
    )(i)
}

// message-data    = nz-number SP ("EXPUNGE" / ("FETCH" SP msg-att))
fn message_data_expunge(i: &[u8]) -> IResult<&[u8], u32> {
    terminated(number, tag_no_case(" EXPUNGE"))(i)
}

// tag             = 1*<any ASTRING-CHAR except "+">
fn imap_tag(i: &[u8]) -> IResult<&[u8], RequestId> {
    map(map_res(take_while1(is_tag_char), from_utf8), |s| {
        RequestId(s.to_string())
    })(i)
}

// This is not quite according to spec, which mandates the following:
//     ["[" resp-text-code "]" SP] text
// However, examples in RFC 4551 (Conditional STORE) counteract this by giving
// examples of `resp-text` that do not include the trailing space and text.
fn resp_text(i: &[u8]) -> IResult<&[u8], (Option<ResponseCode>, Option<&str>)> {
    map(tuple((opt(resp_text_code), text)), |(code, text)| {
        let res = if text.is_empty() {
            None
        } else if code.is_some() {
            Some(&text[1..])
        } else {
            Some(text)
        };
        (code, res)
    })(i)
}

// an response-text if it is at the end of a response. Empty text is then allowed without the normally needed trailing space.
fn trailing_resp_text(i: &[u8]) -> IResult<&[u8], (Option<ResponseCode>, Option<&str>)> {
    map(opt(tuple((tag(b" "), resp_text))), |resptext| {
        resptext.map(|(_, tuple)| tuple).unwrap_or((None, None))
    })(i)
}

// continue-req    = "+" SP (resp-text / base64) CRLF
pub(crate) fn continue_req(i: &[u8]) -> IResult<&[u8], Response> {
    // Some servers do not send the space :/
    // TODO: base64
    map(
        tuple((tag("+"), opt(tag(" ")), resp_text, tag("\r\n"))),
        |(_, _, text, _)| Response::Continue {
            code: text.0,
            information: text.1.map(Cow::Borrowed),
        },
    )(i)
}

// response-tagged = tag SP resp-cond-state CRLF
//
// resp-cond-state = ("OK" / "NO" / "BAD") SP resp-text
//                     ; Status condition
pub(crate) fn response_tagged(i: &[u8]) -> IResult<&[u8], Response> {
    map(
        tuple((
            imap_tag,
            tag(b" "),
            status,
            trailing_resp_text,
            tag(b"\r\n"),
        )),
        |(tag, _, status, text, _)| Response::Done {
            tag,
            status,
            code: text.0,
            information: text.1.map(Cow::Borrowed),
        },
    )(i)
}

// resp-cond-auth  = ("OK" / "PREAUTH") SP resp-text
//                     ; Authentication condition
//
// resp-cond-bye   = "BYE" SP resp-text
//
// resp-cond-state = ("OK" / "NO" / "BAD") SP resp-text
//                     ; Status condition
fn resp_cond(i: &[u8]) -> IResult<&[u8], Response> {
    map(tuple((status, trailing_resp_text)), |(status, text)| {
        Response::Data {
            status,
            code: text.0,
            information: text.1.map(Cow::Borrowed),
        }
    })(i)
}

// response-data   = "*" SP (resp-cond-state / resp-cond-bye /
//                   mailbox-data / message-data / capability-data / quota) CRLF
pub(crate) fn response_data(i: &[u8]) -> IResult<&[u8], Response> {
    delimited(
        tag(b"* "),
        alt((
            resp_cond,
            map(mailbox_data, Response::MailboxData),
            map(message_data_expunge, Response::Expunge),
            message_data_fetch,
            map(capability_data, Response::Capabilities),
            rfc5161::resp_enabled,
            rfc5464::metadata_solicited,
            rfc5464::metadata_unsolicited,
            rfc7162::resp_vanished,
            rfc2087::quota,
            rfc2087::quota_root,
            rfc2971::resp_id,
            rfc4314::acl,
            rfc4314::list_rights,
            rfc4314::my_rights,
        )),
        preceded(
            many0(tag(b" ")), // Outlook server sometimes sends whitespace at the end of STATUS response.
            tag(b"\r\n"),
        ),
    )(i)
}

fn att_list<'a, F, O, E>(f: F) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Vec<O>, E>
where
    F: FnMut(&'a [u8]) -> IResult<&'a [u8], O, E>,
    E: nom::error::ParseError<&'a [u8]>,
{
    delimited(
        char('('),
        separated_list1(char(' '), f),
        preceded(opt(tag(b")")), tag(b"\r\n")),
    )
}

fn follow_att_list<'a, F, O, E>(f: F) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Vec<O>, E>
where
    F: FnMut(&'a [u8]) -> IResult<&'a [u8], O, E>,
    E: nom::error::ParseError<&'a [u8]>,
{
    terminated(
        separated_list1(char(' '), f),
        preceded(opt(tag(b")")), tag(b"\r\n")),
    )
}

#[derive(Debug, Eq, PartialEq)]
pub struct FetchRet<'a> {
    pub attrs: Vec<AttributeValue2<'a>>,
}

impl<'a> FetchRet<'a> {
    pub fn data(&self) -> Option<&'a [u8]> {
        self.attrs.last().and_then(|attr| {
            if let AttributeValue2::BodySection { data, .. } = attr {
                *data
            } else {
                None
            }
        })
    }

    pub fn literal_size(&self) -> Option<usize> {
        self.attrs.last().and_then(|attr| match attr {
            AttributeValue2::BodySection { literal_size, .. } => *literal_size,
            AttributeValue2::Rfc822Header(size) => *size,
            AttributeValue2::Rfc822Text(size) => *size,
            _ => None,
        })
    }

    pub fn is_header(&self) -> bool {
        self.attrs.last().map_or(false, |attr| match attr {
            AttributeValue2::BodySection { section, .. } => {
                section.as_ref().map_or(false, |section| {
                    matches!(
                        section,
                        SectionPath::Full(MessageSection::Header)
                            | SectionPath::Part(_, Some(MessageSection::Header))
                    )
                })
            }
            AttributeValue2::Rfc822Header(_) => true,
            _ => false,
        })
    }

    pub fn body_section_parts(&self) -> Option<Vec<u32>> {
        self.attrs.last().and_then(|attr| {
            if let AttributeValue2::BodySection {
                section: Some(SectionPath::Part(parts, _)),
                ..
            } = attr
            {
                Some(parts.clone())
            } else {
                None
            }
        })
    }
}

fn parse_rsp_fetch(input: &[u8]) -> IResult<&[u8], FetchRet> {
    map(
        tuple((
            tag(b"* "),
            number,
            tag_no_case(" FETCH "),
            att_list(msg_att2),
        )),
        |(_, _, _, attrs)| FetchRet {
            attrs: attrs
                .into_iter()
                .filter(|attr| !matches!(attr, AttributeValue2::Ignored))
                .collect(),
        },
    )(input)
}

pub fn rsp_fetch(input: &str) -> Option<FetchRet> {
    match parse_rsp_fetch(input.as_bytes()) {
        Ok((_, fetch_ret)) => Some(fetch_ret),
        Err(_) => None,
    }
}

fn parse_follow_rsp_fetch(input: &[u8]) -> IResult<&[u8], FetchRet> {
    map(follow_att_list(msg_att2), |attrs| FetchRet {
        attrs: attrs
            .into_iter()
            .filter(|attr| !matches!(attr, AttributeValue2::Ignored))
            .collect(),
    })(input)
}

pub fn follow_rsp_fetch(input: &str) -> Option<FetchRet> {
    match parse_follow_rsp_fetch(input.as_bytes()) {
        Ok((_, fetch_ret)) => Some(fetch_ret),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        parser::rfc3501::{parse_follow_rsp_fetch, parse_rsp_fetch, FetchRet},
        types::*,
    };
    use assert_matches::assert_matches;
    use std::borrow::Cow;

    #[test]
    fn test_rsp_fetch_bodystructure() {
        const RESPONSE: &[u8] = b"* 15 FETCH (BODYSTRUCTURE (\"TEXT\" \"PLAIN\" (\"CHARSET\" \"iso-8859-1\") NIL NIL \"QUOTED-PRINTABLE\" 1315 42 NIL NIL NIL NIL))\r\n";
        match parse_rsp_fetch(RESPONSE) {
            Ok((_, FetchRet { attrs })) => {
                let body = &attrs[0];
                dbg!(body);
                assert!(
                    matches!(*body, AttributeValue2::BodyStructure(_)),
                    "body = {body:?}"
                );
            }
            ret => panic!("unexpected response {ret:?}"),
        }
    }

    #[test]
    fn test_rsp_fetch_ignore() {
        const RESPONSE: &[u8] = b"* 49 FETCH (INTERNALDATE \"02-Jul-2022 21:30:24 +0800\" UID 55 FLAGS (\\Recent) RFC822.SIZE 83801)\r\n";
        match parse_rsp_fetch(RESPONSE) {
            Ok((_, FetchRet { attrs })) => {
                assert_eq!(0, attrs.len());
            }
            ret => panic!("unexpected response {ret:?}"),
        }
    }

    #[test]
    fn test_rsp_fetch_body_quoted() {
        const RESPONSE: &[u8] = b"* 49 FETCH (UID 55 FLAGS (\\Recent) RFC822.SIZE 83801 BODY[HEADER.FIELDS (DATE FROM SUBJECT CONTENT-TYPE X-MS-TNEF-CORRELATOR CONTENT-CLASS IMPORTANCE PRIORITY X-PRIORITY THREAD-TOPIC REPLY-TO)] \"content\"\r\n";
        match parse_rsp_fetch(RESPONSE) {
            Ok((_, FetchRet { attrs })) => {
                assert_eq!(1, attrs.len());
                let body = &attrs[0];
                dbg!(body);
                let expected_content = b"content";
                if let AttributeValue2::BodySection {
                    data: Some(content),
                    ..
                } = body
                {
                    assert_eq!(content, expected_content);
                } else {
                    panic!("unexpected body type: {body:?}");
                }
            }
            ret => panic!("unexpected response {ret:?}"),
        }
    }

    #[test]
    fn test_rsp_fetch_body_literal() {
        const RESPONSE: &[u8] = b"* 49 FETCH (UID 55 RFC822.SIZE 83801 BODY[HEADER.FIELDS (DATE FROM SUBJECT CONTENT-TYPE X-MS-TNEF-CORRELATOR CONTENT-CLASS IMPORTANCE PRIORITY X-PRIORITY THREAD-TOPIC REPLY-TO)] {250}\r\n";
        match parse_rsp_fetch(RESPONSE) {
            Ok((_, fetch_ret)) => {
                assert_eq!(1, fetch_ret.attrs.len());

                let body = &fetch_ret.attrs[0];
                dbg!(body);
                if let AttributeValue2::BodySection {
                    index: None,
                    literal_size: Some(size),
                    data: None,
                    ..
                } = body
                {
                    assert_eq!(*size, 250);
                } else {
                    panic!("unexpected body type: {body:?}");
                }

                assert!(fetch_ret.is_header());
            }
            ret => panic!("unexpected response {ret:?}"),
        }
    }

    #[test]
    fn test_follow_rsp_fetch_part_body() {
        const RESPONSE: &[u8] = b"BODY[1.2] {5964}\r\n";
        match parse_follow_rsp_fetch(RESPONSE) {
            Ok((_, FetchRet { attrs })) => {
                assert_eq!(1, attrs.len());
                let body = &attrs[0];
                dbg!(body);

                if let AttributeValue2::BodySection {
                    section,
                    index: None,
                    literal_size: Some(size),
                    data: None,
                    ..
                } = body
                {
                    assert_eq!(*size, 5964);
                    assert_eq!(*section, Some(SectionPath::Part(vec![1, 2], None)));
                } else {
                    panic!("unexpected body type: {body:?}");
                }
            }
            ret => panic!("unexpected response {ret:?}"),
        }
    }

    #[test]
    fn test_follow_rsp_fetch_bodystructure() {
        const RESPONSE: &[u8] = b"BODYSTRUCTURE (\"TEXT\" \"PLAIN\" (\"CHARSET\" \"iso-8859-1\") NIL NIL \"QUOTED-PRINTABLE\" 1315 42 NIL NIL NIL NIL))\r\n";
        match parse_follow_rsp_fetch(RESPONSE) {
            Ok((_, FetchRet { attrs })) => {
                let body = &attrs[0];
                dbg!(body);
                assert!(
                    matches!(*body, AttributeValue2::BodyStructure(_)),
                    "body = {body:?}"
                );
            }
            ret => panic!("unexpected response {ret:?}"),
        }
    }

    #[test]
    fn test_fetchret_data() {
        const RESPONSE: &[u8] = b"* 49 FETCH (UID 55 FLAGS (\\Recent) RFC822.SIZE 83801 BODY[HEADER.FIELDS (DATE FROM SUBJECT CONTENT-TYPE X-MS-TNEF-CORRELATOR CONTENT-CLASS IMPORTANCE PRIORITY X-PRIORITY THREAD-TOPIC REPLY-TO)] \"content\"\r\n";

        let (_, fetch_ret) = parse_rsp_fetch(RESPONSE).expect("failed to parse FETCH response");
        assert_eq!(fetch_ret.data(), Some(b"content" as &[u8]));
        assert_eq!(fetch_ret.attrs.len(), 1);
    }

    #[test]
    fn test_fetchret_is_header() {
        // Test RFC822.HEADER
        let response1 = b"* 49 FETCH (UID 55 RFC822.HEADER {625}\r\n";
        let (_, fetch_ret1) = parse_rsp_fetch(response1).expect("failed to parse FETCH response");
        assert!(fetch_ret1.is_header());
        assert_eq!(fetch_ret1.literal_size(), Some(625));

        // Test BODY[HEADER]
        let response2 = b"* 49 FETCH (BODY[HEADER] {625}\r\n";
        let (_, fetch_ret2) = parse_rsp_fetch(response2).expect("failed to parse FETCH response");
        assert!(fetch_ret2.is_header());
        assert_eq!(fetch_ret1.literal_size(), Some(625));

        // Test BODY[1.HEADER]
        let response3 = b"* 49 FETCH (BODY[1.HEADER] {625}\r\n";
        let (_, fetch_ret3) = parse_rsp_fetch(response3).expect("failed to parse FETCH response");
        assert!(fetch_ret3.is_header());
        assert_eq!(fetch_ret1.literal_size(), Some(625));

        // Test non-header response
        let response4 = b"* 49 FETCH (UID 55 BODY[] {625}\r\n";
        let (_, fetch_ret4) = parse_rsp_fetch(response4).expect("failed to parse FETCH response");
        assert!(!fetch_ret4.is_header());
        assert_eq!(fetch_ret1.literal_size(), Some(625));
    }

    // ------------------------------------
    #[test]
    fn test_list() {
        match super::mailbox(b"iNboX ") {
            Ok((_, mb)) => {
                assert_eq!(mb, "INBOX");
            }
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }

    #[test]
    fn test_envelope() {
        let env = br#"ENVELOPE ("Wed, 17 Jul 1996 02:23:25 -0700 (PDT)" "IMAP4rev1 WG mtg summary and minutes" (("Terry Gray" NIL "gray" "cac.washington.edu")) (("Terry Gray" NIL "gray" "cac.washington.edu")) (("Terry Gray" NIL "gray" "cac.washington.edu")) ((NIL NIL "imap" "cac.washington.edu")) ((NIL NIL "minutes" "CNRI.Reston.VA.US") ("John Klensin" NIL "KLENSIN" "MIT.EDU")) NIL NIL "<B27397-0100000@cac.washington.edu>") "#;
        match super::msg_att_envelope(env) {
            Ok((_, AttributeValue::Envelope(_))) => {}
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }

    #[test]
    fn test_opt_addresses() {
        let addr = b"((NIL NIL \"minutes\" \"CNRI.Reston.VA.US\") (\"John Klensin\" NIL \"KLENSIN\" \"MIT.EDU\")) ";
        match super::opt_addresses(addr) {
            Ok((_, _addresses)) => {}
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }

    #[test]
    fn test_opt_addresses_no_space() {
        let addr =
            br#"((NIL NIL "test" "example@example.com")(NIL NIL "test" "example@example.com"))"#;
        match super::opt_addresses(addr) {
            Ok((_, _addresses)) => {}
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }

    #[test]
    fn test_addresses() {
        match super::address(b"(\"John Klensin\" NIL \"KLENSIN\" \"MIT.EDU\") ") {
            Ok((_, _address)) => {}
            rsp => panic!("unexpected response {rsp:?}"),
        }

        // Literal non-UTF8 address
        match super::address(b"({12}\r\nJoh\xff Klensin NIL \"KLENSIN\" \"MIT.EDU\") ") {
            Ok((_, _address)) => {}
            rsp => panic!("unexpected response {rsp:?}"),
        }
    }

    #[test]
    fn test_capability_data() {
        // Minimal capabilities
        assert_matches!(
            super::capability_data(b"CAPABILITY IMAP4rev1\r\n"),
            Ok((_, capabilities)) => {
                assert_eq!(capabilities, vec![Capability::Imap4rev1])
            }
        );

        assert_matches!(
            super::capability_data(b"CAPABILITY XPIG-LATIN IMAP4rev1 STARTTLS AUTH=GSSAPI\r\n"),
            Ok((_, capabilities)) => {
                assert_eq!(capabilities, vec![
                    Capability::Atom(Cow::Borrowed("XPIG-LATIN")),
                    Capability::Imap4rev1,
                    Capability::Atom(Cow::Borrowed("STARTTLS")),
                    Capability::Auth(Cow::Borrowed("GSSAPI")),
                ])
            }
        );

        assert_matches!(
            super::capability_data(b"CAPABILITY IMAP4rev1 AUTH=GSSAPI AUTH=PLAIN\r\n"),
            Ok((_, capabilities)) => {
                assert_eq!(capabilities, vec![
                    Capability::Imap4rev1,
                    Capability::Auth(Cow::Borrowed("GSSAPI")),
                    Capability::Auth(Cow::Borrowed("PLAIN")),
                ])
            }
        );

        // Capability command must contain IMAP4rev1
        assert_matches!(
            super::capability_data(b"CAPABILITY AUTH=GSSAPI AUTH=PLAIN\r\n"),
            Err(_)
        );
    }
}
